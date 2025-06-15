from handler import Handler
from config_reader import Reader
import json
import getopt
import sys

class Main:

    check_handler = Handler()
    reader = Reader()
    beautify = True
    output_file = None
    file_path = ''

    def __init__(self, file_path, beautify = True, output_file = None):
        self.beautify = beautify
        self.output_file = output_file 
        self.filepath = file_path

    def check(self):
        
        filepath = self.filepath
        bench = self.reader.read_and_translate(filepath)
        
        
        if bench is None:
            result = {"err_type": -1, "err_message": "fail to decode file format"}
            self.output(result)
            print("fail to decode file format")
            return
        
       
        
        
        check_type = bench[0]
        result = None  
        
        try:
            if check_type == "check1": # Check whether policy has totally exclude the topics
                result = self.check_handler.check_complete_intersection_with_topics_separately(bench[3], bench[2], with_action=True)
            elif check_type == "check2": # Check whether two policy has intersection
                result = self.check_handler.check_complete_intersection_with_policy_separately(bench[1], bench[2])
            elif check_type == "check3": # Check whether policy1 is overly permissive than policy2
                result = self.check_handler.check_overly_permissive_with_policy(bench[1], bench[2])
            elif check_type == "check4": # Infer from Deny statements and check
                result = self.check_handler.check_infer_policy(bench[1])
            elif check_type == "check5":  # Check 5: Publish-Subscribe 
                result = self.check_handler.check_publish_subscribe_relation(bench[1])
            else:
                result = {"err_type": -1, "err_message": f"unknow type check: {check_type}"}
        except Exception as e:
            import traceback
            result = {"err_type": -1, "err_message": f"error processing: {str(e)}", "traceback": traceback.format_exc()}
        
        self.output(result)
        print(f"Check type: {check_type}")
        
    def output(self, result, beautify = True):
        filepath = None
        if not self.output_file:
            if not beautify:
                print(json.dumps(result)) 
            else:
                print(json.dumps(result, indent=4)) 
        else:
            filepath = self.output_file
            with open(filepath, 'w') as f:
                if not beautify:
                    f.write(json.dumps(result))
                else:
                    result = json.dumps(result, indent=4)
                    f.write(result)
        if self.output_file:
           print(f"[+] Result written to {self.output_file}")
def main(argv):
    input_file = None
    output_file = None
    try:
       opts, args = getopt.getopt(argv,"hi:o:",["ifile=","ofile="])
    except getopt.GetoptError:
       print('main.py -i <inputfile> -o <outputfile>')
       sys.exit(2)
    for opt, arg in opts:
        if opt == '-h':
            print('main.py -i <inputfile> -o <outputfile>')
            sys.exit()
        elif opt in ("-i", "--ifile"):
            input_file = arg
        elif opt in ("-o", "--ofile"):
            output_file = arg
    # print(input_file, output_file)

    Main(file_path=input_file, output_file=output_file).check()

if __name__ == '__main__':
    main(sys.argv[1:])