import xmltodict
import yaml
import os
from rich.console import Console
from rich.panel import Panel
from rich.syntax import Syntax
from rich import prompt
from json import dumps

console = Console()

def get_xml_from_user():
    """Get XML input from user via interactive dialog."""
    console.print(Panel.fit("XML Input Options", border_style="yellow"))

    input_method = prompt.Prompt.ask(
        "How would you like to provide XML?",
        choices=["paste", "file"],
        default="paste"
    )

    xml_content = ""

    if input_method == "paste":
        console.print("Paste your XML content below and type 'END_XML' on a new line when finished:")
        xml_lines = []
        while True:
            try:
                line = input()
                if line.strip() == "END_XML":
                    break
                xml_lines.append(line)
            except EOFError:
                break
        xml_content = "\n".join(xml_lines)
    else:  # file
        file_path = prompt.Prompt.ask("Enter the path to your XML file")
        try:
            with open(file_path, 'r') as file:
                xml_content = file.read()
        except FileNotFoundError:
            console.print(f"[bold red]Error:[/bold red] File not found: {file_path}")
            return get_xml_from_user()  # Recursively ask again
        except Exception as e:
            console.print(f"[bold red]Error:[/bold red] {str(e)}")
            return get_xml_from_user()  # Recursively ask again

    return xml_content

# Get XML input from user
xml_code = get_xml_from_user()

# Check if we got valid XML content
if not xml_code.strip():
    console.print("[bold red]Error:[/bold red] No XML content provided. Exiting.")
    exit(1)

try:
    # Parse XML to dictionary
    xml_dict = xmltodict.parse(xml_code)

    # Extract the first entry name to use in filenames
    entry_name = xml_dict['entry']['@name']

    # Convert to JSON and YAML
    json_data = dumps(xml_dict, indent=4)
    yaml_data = yaml.dump(xml_dict, default_flow_style=False, sort_keys=False)
except Exception as e:
    console.print(f"[bold red]Error:[/bold red] {str(e)}")
    exit(1)

# Save to files
json_filename = f"{entry_name}.json"
yaml_filename = f"{entry_name}.yaml"

with open(json_filename, 'w') as json_file:
    json_file.write(json_data)

with open(yaml_filename, 'w') as yaml_file:
    yaml_file.write(yaml_data)

# Display in console with rich formatting
panel_xml = Panel.fit("Source XML", border_style="red")
console.print(panel_xml)
console.print(Syntax(xml_code, "xml", theme="default", background_color="default"))

panel_json = Panel.fit(f"Resulting JSON (saved to {json_filename})", border_style="blue")
console.print(panel_json)
console.print(Syntax(json_data, "json", theme='default', background_color="default"))

panel_yaml = Panel.fit(f"Resulting YAML (saved to {yaml_filename})", border_style="green")
console.print(panel_yaml)
console.print(Syntax(yaml_data, "yaml", theme='default', background_color="default"))
