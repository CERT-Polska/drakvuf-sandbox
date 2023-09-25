from dataclasses import dataclass


@dataclass
class VmiGuidInfo:
    version: str
    guid: str
    filename: str
