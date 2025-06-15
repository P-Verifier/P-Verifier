# read from benchmark for now

import json
import os


class Reader():

    def __init__(self):
        pass

    __actions = ['iot:Connect', 'iot:Publish', 'iot:Subscribe', 'iot:Receive'] 

    def reader(self, filename):
        with open(filename) as f:
            content = f.read()
            f.close()
            try:
                content = json.loads(content)
            except Exception as e:
                print("Input Error")
                return None
            try:
                
                if "Expected" in content:
                    expected = content["Expected"]
                    check_type = f"check{expected['type']}" if 'type' in expected else "check5"
                    
                   
                    if "Statement1" in content:
                        if "Statement2" in content:
                            return check_type, content["Statement1"], content["Statement2"]
                        else:
                            if check_type == "check4" or check_type == "check5":
                                return check_type, content["Statement1"]
                            else:
                               
                                deny_topics = []
                                if "NotReceive" in expected:
                                    deny_topics.extend([(topic, self.__actions[2]) for topic in expected["NotReceive"]])
                                if "NotPublish" in expected:
                                    deny_topics.extend([(topic, self.__actions[1]) for topic in expected["NotPublish"]])
                                return check_type, expected, content["Statement1"], deny_topics
                
                
                keys = content.keys()
                if "SecurityProperty" in keys:
                    expected = content["SecurityProperty"]
                    check_type = expected['type']
                else:
                    check_type = "check1"
                    
                if check_type == "check1": 
                    return check_type, expected, content["policy1"]['Statement']
                if check_type == "check2": 
                    return check_type, content["policy1"]['Statement'], content["policy2"]['Statement']
                if check_type == "check3":
                    return check_type, content["policy1"]['Statement'], content["policy2"]['Statement']
                if check_type == "check4":
                    return check_type, content["policy1"]['Statement']
                if check_type == "check5":
                    return check_type, content["policy1"]['Statement']
            except Exception as e:
                print(f"File Format Error: {str(e)}")
                import traceback
                traceback.print_exc()
                return None

    def translate(self, config_middle_values):
        check_type = config_middle_values[0]
        
        
        print(f"[DEBUG] translate方法接收到的中间值: {config_middle_values}")
        
        if check_type == "check1":
            expected = config_middle_values[1]
            keys = expected.keys()
            deny_cache = []
            allow_cache = []
            if 'ShouldNotReceive' in keys:
                for cell in expected["ShouldNotReceive"]:
                    deny_cache.append([cell, self.__actions[2]])
            if 'NotReceive' in keys: 
                for cell in expected["NotReceive"]:
                    deny_cache.append([cell, self.__actions[2]])
            if 'ShouldNotPublish' in keys:
                for cell in expected["ShouldNotPublish"]:
                    deny_cache.append([cell, self.__actions[1]])
            if 'NotPublish' in keys:  
                for cell in expected["NotPublish"]:
                    deny_cache.append([cell, self.__actions[1]])
            if "Receive" in keys:
                for cell in expected["Receive"]:
                    allow_cache.append([cell, self.__actions[2]])
            if "Publish" in keys:
                for cell in expected["Publish"]:
                    allow_cache.append([cell, self.__actions[1]])
            return check_type, allow_cache, deny_cache, {"Statement": config_middle_values[2]}
        
        if check_type == "check4" or check_type == "check5":
           
            if isinstance(config_middle_values[1], list):
                return check_type, {"Statement": config_middle_values[1]}
            else:
                return check_type, config_middle_values[1]
        else:
            
            if isinstance(config_middle_values[1], list) and isinstance(config_middle_values[2], list):
                return check_type, {"Statement": config_middle_values[1]}, {"Statement": config_middle_values[2]}
            else:
                return check_type, config_middle_values[1], config_middle_values[2]

    def read_and_translate(self, filename):
        middle_value = self.reader(filename)
        if middle_value:
            return self.translate(middle_value)

    def benchmark_walker(self):
        file_cache = []
        # for root, dirs, files in os.walk("./policy_benchmark", topdown=False):
        for root, dirs, files in os.walk("./accurate_benchmark", topdown=False):
            for name in files:
                file_cache.append(os.path.join(root, name))
        return file_cache

def test():
    reader = Reader()
    # a = reader.read_and_translate('./policy_benchmark/user_policies/deny_topic/deny_topic_wildcard.json')
    # print(a[1])
    # print(a[2])
    print(reader.benchmark_walker())

# test()