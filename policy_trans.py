import json
import copy

def convert_to_standard_format(input_data: dict, check_type: str = "check5") -> dict:
    output_data = {}

    
    if check_type.startswith("check"):
        check_number = check_type.replace("check", "")
    else:
        check_number = check_type

    if check_type == "check4":
        output_data["SecurityProperty"] = {"type": check_type}
    elif check_type == "check1":
        output_data["SecurityProperty"] = {
            "type": check_type,
            "ShouldNotReceive": [],
            "ShouldNotPublish": []
        }
    else:
        output_data["Expected"] = {"type": int(check_number)}

    if "Statement" in input_data:
        if check_type in ["check1", "check4", "check5"]:
            output_data["policy1"] = {
                "Statement": input_data["Statement"]
            }
        else:
            output_data["policy1"] = {
                "Statement": input_data["Statement"]
            }
            output_data["policy2"] = {
                "Statement": input_data["Statement"]  
            }
    elif "policy1" in input_data and "policy2" in input_data:
        output_data["policy1"] = input_data["policy1"]
        output_data["policy2"] = input_data["policy2"]
    else:
        output_data["policy1"] = input_data

    return output_data