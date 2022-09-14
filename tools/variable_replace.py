# This is a class for replace variables like ${iot:ClientId}
# Now just a string replacement

# from z3 import *
import json
from os import replace
from tools.policy_reader import test_fake_read

class PolicyVariableReplacer:

    __policies = None 

    def __replace_client_id(self, string, connect_bug=True):
        if '${iot:ClientId}' in string:
            flag = True
        else:
            flag = False
        if connect_bug:
            # print(string)
            string = string.replace('${iot:ClientId}', '*')

        return string, flag

    def replace(self, policy):
        statements = policy['Statement']
        flag = False
        for smt in statements:
            if smt['Action'] == "iot:Connect" or 'iot:Connect' in smt['Action']:
                connect_resource = smt['Resource']
                if type(connect_resource) == str:
                    connect_resource, _point = self.__replace_client_id(connect_resource)
                    if _point == True:
                        flag = True
                    smt['Resource'] = connect_resource
                elif type(connect_resource) == list:
                    for i in range(len(connect_resource)):
                        line = connect_resource[i]
                        line, _point = self.__replace_client_id(line)
                        smt['Resource'][i] = line 
                        if _point == True:
                            flag = True
            else:
                other_resource = smt['Resource']
                if type(other_resource) == str:
                    other_resource, _point = self.__replace_client_id(other_resource, connect_bug = flag)
                    smt['Resource'] = other_resource 
                elif type(other_resource) == list:
                    for i in range(len(other_resource)):
                        line = other_resource[i]
                        # print(line)
                        line, _point = self.__replace_client_id(line, connect_bug = flag)
                        # print(line)
                        smt['Resource'][i] = line 


    def replace_policies(self, policies = None):
        if not policies:
            policies = self.__policies
        for policy in policies:
            self.replace(policy)

        # print(policies)
    def input(self, policies):
        self.__policies = policies
        

def test():
   replacer = PolicyVariableReplacer() 
   policies = test_fake_read() 
   print(replacer.replace_policies(policies))

if __name__ == '__main__':
    test()
    
