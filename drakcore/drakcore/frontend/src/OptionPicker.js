import React from "react";

class OptionPicker extends React.Component {
  constructor(props) {
    super(props);
    this.state = {
      selected: this.props.defaultSelection,
    };
    this.handleChange = this.handleChange.bind(this);
  }

  handleChange(event) {
    const value = event.target.value;
    this.setState({ selected: value });
    this.props.onChange(value);
  }

  renderOption(item, index) {
    return (
      <option key={index} value={item.key}>
        {item.value}
      </option>
    );
  }

  render() {
    return (
      <select
        value={this.state.selected || ""}
        className={`form-control ${this.props.className}`}
        onChange={this.handleChange}
      >
        {this.props.data.map(this.renderOption)}
      </select>
    );
  }
}

export default OptionPicker;
