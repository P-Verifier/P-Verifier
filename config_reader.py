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
                keys = content.keys()
                if "Expected" in keys:
                    expected = content["Expected"]
                    check_type = expected['type']
                else:
                    check_type = 1
                if check_type == 0: # Policy And Excepted
                    return check_type, expected, content['Statement2']
                if check_type == 1: # Policy And Policy
                    return check_type, content['Statement1'], content['Statement2']
                if check_type == 2:
                    return check_type, expected, content['Statement2']
            except:
                print("File Format Error")
                return None

    def translate(self, config_middle_values):
        check_type = config_middle_values[0]
        if check_type == 0:
            expected = config_middle_values[1]
            keys = expected.keys()
            deny_cache = []
            allow_cache = []
            if 'NotReceive' in keys:
                for cell in expected["NotReceive"]:
                    deny_cache.append([cell, self.__actions[2]])
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
        elif check_type == 2:
            expected = config_middle_values[1]
            keys = expected.keys()
            deny_cache = []
            allow_cache = []
            if 'NotReceive' in keys:
                for cell in expected["NotReceive"]:
                    deny_cache.append([cell, self.__actions[2]])
            if 'NotPublish' in keys:
                for cell in expected["NotPublish"]:
                    deny_cache.append([cell, self.__actions[1]])
            if "Receive" in keys:
                for cell in expected["Receive"]:
                    allow_cache.append([cell, self.__actions[2]])
            if "Publish" in keys:
                for cell in expected["Publish"]:
                    allow_cache.append([cell, self.__actions[1]])
            # print(config_middle_values[2])
            return check_type, allow_cache, deny_cache, {"Statement": config_middle_values[2]}
        else:
            return check_type, {"Statement": config_middle_values[1]} , {"Statement": config_middle_values[2]}

    def read_and_translate(self, filename):
        middle_value = self.reader(filename)
        if middle_value:
            return self.translate(middle_value)

    def benchmark_walker(self):
        file_cache = []
        for root, dirs, files in os.walk("./policy_benchmark", topdown=False):
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