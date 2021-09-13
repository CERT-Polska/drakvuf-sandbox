import logging
import sys

import regex as re
from oletools.olevba import VBA_Parser

# Temporary workaround till oletools 0.56 are released.
VBA_Parser.detect_vba_stomping = lambda self: False


"""
Following code which generates a vba macro callgraph comes from Vba2Graph
project: https://github.com/MalwareCantFly/Vba2Graph. It includes small bug
fixes and added support for python3.
"""


LINE_SEP = "\n"


class Graph:
    """Simple implementation of directed graph to minimalize number of dependencies."""

    def __init__(self):
        self.nodes = set()
        self.edges = set()

    def add_node(self, node):
        self.nodes.add(node)

    def add_edge(self, src, dst):
        self.edges.add((src, dst))


def vba2graph_from_vba_object(filepath):
    logging.info("Extracting macros from file")
    full_vba_code = ""
    vba_parser = VBA_Parser(filepath)
    for (
        subfilename,
        stream_path,
        vba_filename,
        vba_code,
    ) in vba_parser.extract_macros():
        # workaround till oletools version 0.56
        if isinstance(vba_code, bytes):
            vba_code = vba_code.decode("latin1", errors="replace")
        full_vba_code += vba_code
    vba_parser.close()
    return full_vba_code


def vba_seperate_lines(input_vba_content):
    # Normalize different line seperators.
    input_vba_content = input_vba_content.replace("\r\n", LINE_SEP)

    # Concat VBA lines that were split by " _".
    input_vba_content = input_vba_content.replace(" _" + LINE_SEP, " ")
    return input_vba_content.split(LINE_SEP)


def vba_clean_whitespace(vba_content_lines):
    result_vba_lines = []
    for vba_line in vba_content_lines:
        # Remove leading and trailing whitespace
        # & reduce multiple whitespaces into one space.
        vba_line = " ".join(vba_line.split())

        # Check and discard empty lines.
        if vba_line == "":
            continue
        result_vba_lines.append(vba_line)
    return result_vba_lines


def vba_clean_metadata(vba_content_lines):
    result_vba_lines = []
    for vba_line in vba_content_lines:
        # Check and discard empty lines.
        if vba_line.startswith("Attribute") or vba_line.startswith("'"):
            continue

        # Crop inline comments.
        possible_inline_comment_pos = vba_line.find(" '")
        if possible_inline_comment_pos > -1:
            # Look for '"' after the ', in order to find FP inline comment detections.
            if vba_line.find('"', possible_inline_comment_pos) < 0:
                inline_comment_pos = possible_inline_comment_pos
                vba_line = vba_line[:inline_comment_pos]
        result_vba_lines.append(vba_line)
    return result_vba_lines


def vba_extract_functions(vba_content_lines):
    """Seperates the input VBA code into functions

    Args:
        vba_content_lines (string[]): VBA code lines without comments, metadata or spaces

    Returns:
        dict[func_name]=func_code: Dictionary of VBA functions found
    """
    vba_func_dict = {}
    inside_function = False
    func_name = ""

    for vba_line in vba_content_lines:
        # I) Handle External Function Declaration.

        # Create dummpy empty function with func_name:
        # mcvWGqJifEVHwB (URLDownloadToFileA)
        # Examples:
        #   Private Declare Function NyKQpQhtmrFfWX Lib "kernel32" Alias "lstrcmpA" (ByVal pCaller As Long,..
        #   - would become: NyKQpQhtmrFfWX (lstrcmpA) (External)
        #   Private Declare PtrSafe Function mcvWGqJifEVHwB Lib "urlmon" Alias "URLDownloadToFileA" (ByVal pfsseerwseer As Long,...
        #   - would become: mcvWGqJifEVHwB (URLDownloadToFileA) (External)
        if " Lib " in vba_line and " Alias " in vba_line and not inside_function:
            if " Function " in vba_line:
                func_type = " Function "
            else:
                func_type = " Sub "

            declared_func_name = vba_line[
                vba_line.find(func_type) + len(func_type) : vba_line.find(" Lib ")
            ]
            external_func_name = vba_line[
                vba_line.find(' Alias "')
                + len(' Alias "') : vba_line.find(
                    '" (', vba_line.find(' Alias "') + len(' Alias "')
                )
            ]
            func_name = (
                declared_func_name + " (" + external_func_name + ")" + " (External)"
            )

            if "libc.dylib" in vba_line:
                func_name += "(Mac)"

            vba_func_dict[func_name] = ""
            continue

        # Create dummy empty function with func_name that do not have Alias:
        # Examples:
        #   Public Declare PtrSafe Sub Sleep Lib "kernel32" (ByVal dwMilliseconds As LongPtr)
        #   - would become: Sleep
        #   Public Declare Sub Sleep Lib "kernel32" (ByVal dwMilliseconds As Long)
        #   - would become: Sleep
        if " Lib " in vba_line and not inside_function:
            if " Function " in vba_line:
                func_type = " Function "
            else:
                func_type = " Sub "
            func_name = (
                vba_line[
                    vba_line.find(func_type) + len(func_type) : vba_line.find(" Lib ")
                ]
                + " (External)"
            )

            if "libc.dylib" in vba_line:
                func_name += "(Mac)"

            vba_func_dict[func_name] = ""
            continue

        # II) Handle Regular Function Declaration.
        # Look for function start keywords.
        func_start_pos = max(vba_line.find("Sub "), vba_line.find("Function "))

        # Some macros have the word "Function" as string inside a code line.
        # This should remove FP funtions, by checking the line start.
        legit_declare_line_start = False
        if (
            vba_line.startswith("Sub")
            or vba_line.startswith("Function")
            or vba_line.startswith("Private")
            or vba_line.startswith("Public")
        ):
            legit_declare_line_start = True

        is_func_end = vba_line.startswith("End Sub") or vba_line.startswith(
            "End Function"
        )

        # Check if we've reached the end of a function.
        if is_func_end:
            inside_function = False
            continue

        # Check if we've hit a new function.
        elif legit_declare_line_start and func_start_pos > -1:
            inside_function = True

            # Extract function name from declaration.
            if "Function " in vba_line:
                func_name = vba_line[
                    (func_start_pos + len("Function ")) : vba_line.find("(")
                ]
            elif "Sub " in vba_line:
                func_name = vba_line[
                    (func_start_pos + len("Sub ")) : vba_line.find("(")
                ]
            else:
                logging.error("Error parsing function name")
                sys.exit(1)

        elif inside_function:
            if func_name in vba_func_dict:
                # Append code to to an existing function.
                vba_func_dict[func_name] += LINE_SEP + vba_line
            else:
                # Create a new function name inside the dict
                # & add the first line of code.
                vba_func_dict[func_name] = vba_line

        # We are in a global section code line.
        else:
            pass
    return vba_func_dict


def vba_extract_properties(vba_content_lines):
    """Find and extract the use of VBA Properties, in order to obfuscate macros

    Args:
        vba_content_lines (string[]): VBA code lines without comments, metadata or spaces

    Returns:
        dict[property_name]=property_code: Dictionary of VBA Properties found
    """
    vba_prop_dict = {}
    inside_property = False
    prop_name = ""

    for vba_line in vba_content_lines:
        # Look for property start keywords.
        prop_start_pos = max(
            vba_line.find("Property Let "), vba_line.find("Property Get ")
        )

        # Look for property end keywords.
        is_prop_end = vba_line.startswith("End Property")

        # Check if we've reached the end of a property.
        if is_prop_end:
            inside_property = False
            continue

        # Check if we've hit a new property.
        elif prop_start_pos > -1:
            inside_property = True

            # Extract property name from declaration.
            if "Property Let " in vba_line or "Property Get " in vba_line:
                prop_name = (
                    vba_line[
                        (prop_start_pos + len("Property Let ")) : vba_line.find("(")
                    ]
                    + " (Property)"
                )

            else:
                logging.error("Error parsing property name")
                sys.exit(1)

        # Check if we are inside a property code.
        elif inside_property:
            if prop_name in vba_prop_dict:
                # Append code to to an existing property.
                vba_prop_dict[prop_name] += LINE_SEP + vba_line
            else:
                # Create a new property name inside the dict
                # & add the first line of code.
                vba_prop_dict[prop_name] = vba_line

        # We are in a global section code line.
        else:
            pass

    return vba_prop_dict


def create_call_graph(vba_func_dict):
    dg = Graph()
    for func_name in vba_func_dict:
        dg.add_node(func_name)

    # Analyze function calls.
    for func_name in vba_func_dict:
        func_code = vba_func_dict[func_name]
        # Split function code into tokens.
        func_code_tokens = list(
            filter(None, re.split('["(, \\-!?:\r\n)&=.><]+', func_code))
        )

        # Inside each function's code, we are looking for a function name.
        for func_name1 in vba_func_dict:
            orig_func_name = func_name1
            # In case of a external function declaration,
            # we should use only the Alias from the function name:
            #   mcvWGqJifEVHwB (URLDownloadToFileA)
            #   - would become: mcvWGqJifEVHwB.
            space_pos = func_name1.find(" ")
            if space_pos > -1:
                func_name1 = func_name1[:space_pos]

            if func_name != func_name1 and func_name1 in list(func_code_tokens):
                dg.add_edge(func_name, orig_func_name)
    return dg


def vba2graph_gen(input_vba_content):
    vba_content_lines = vba_seperate_lines(input_vba_content)
    vba_content_lines_no_whitespace = vba_clean_whitespace(vba_content_lines)
    vba_content_lines_no_metadata = vba_clean_metadata(vba_content_lines_no_whitespace)
    vba_func_dict = vba_extract_functions(vba_content_lines_no_metadata)
    vba_prop_dict = vba_extract_properties(vba_content_lines_no_metadata)

    # treat properties like functions and merge both dictionaries
    vba_func_dict = dict(vba_func_dict.items() | vba_prop_dict.items())
    dg = create_call_graph(vba_func_dict)
    return dg


def find_outer_nodes(dg):
    inner_nodes = set()
    for edge in dg.edges:
        inner_nodes.add(edge[1])
    inner_nodes = list(inner_nodes)
    outer_nodes = list(filter(lambda n: n not in inner_nodes, dg.nodes))
    return outer_nodes


def get_outer_nodes_from_vba_file(filename):
    try:
        input_vba_content = vba2graph_from_vba_object(filename)
        dg = vba2graph_gen(input_vba_content)
        return find_outer_nodes(dg)
    except Exception as ex:
        logging.warning("Something went wrong. Perhaps this is not an office document.")
        logging.warning(ex)
        return None
