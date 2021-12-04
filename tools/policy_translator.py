# This is a script to convert a policy file to the regular what we want it to be 

import re
from collections import defaultdict

class PolicyTranslator:
    
  
    actions = ['iot:Connect', 'iot:Publish', 'iot:Subscribe', 'iot:Receive']
    prefix = re.compile('^arn:aws:iot:[a-z\-0-9]+:[0-9]+:')
    def translate_smt(self, smt):
        result = []
        smt_action = smt['Action'] 
        smt_effect = smt['Effect']
        smt_resource = smt['Resource']
        if type(smt_resource) == str:
            smt_resource = [smt_resource]

        for action in self.actions:
            if type(smt_action) == str:
                smt_action = [smt_action]
            for to_do_action in smt_action:
                if re.match(to_do_action, action):
                    c = {
                        'Action': action,
                        'Effect': smt_effect,
                        'Resource': smt_resource
                    } 
                    result.append(c)
        return result

    def translate(self, policy_json):
        result = []
        smts = policy_json['Statement']
        smts = map(self.translate_smt, smts)
        for smt in smts:
            for cell in smt:
                result.append(cell)
        return { "Statement" : result }

    # To translate a list of policies
    def translate_policies(self, smts):
        return list(map(self.translate, smts))

    # delete the arn form
    def deep_translate(self, policy):
        
        policy = self.translate(policy)
        policy = self.subscribe_translate(policy)
        for i in range(len(policy["Statement"])):
            smt = policy["Statement"][i]
            if type(smt["Resource"]) == str:
                smt["Resource"] = [smt["Resource"]]

        for i in range(len(policy["Statement"])):
            cache = []
            smt = policy["Statement"][i]
            for index in range(len(smt["Resource"])):
                resource = smt["Resource"][index]
                match = self.prefix.search(resource)
                if match:
                    resource = resource[match.end():]
                cache.append(resource)
                # print(resource)
            smt["Resource"] = cache
        return policy
    
    def subscribe_translate(self, policy):
        # Just transfer topicfilter to topic 
        policy = self.translate(policy)
        for i in range(len(policy["Statement"])):
            smt = policy["Statement"][i]
            if type(smt["Resource"]) == str:
                smt["Resource"] = [smt["Resource"]]
        for i in range(len(policy["Statement"])):
            smt = policy["Statement"][i]
            if smt["Action"] == "iot:Subscribe":
                cache = []
                for index in range(len(smt["Resource"])):
                    resource = smt["Resource"][index]
                    match = self.prefix.search(resource)
                    if match:
                        new_resource = resource[match.end():]
                        if new_resource.startswith("topicfilter"):
                            new_resource = 'topic' + new_resource[len("topicfilter"):]
                        resource = resource[match.start():match.end()] + new_resource
                    else:
                        if resource.startswith("topicfilter"):
                            resource = 'topic' + resource[len("topicfilter"):] 
                    cache.append(resource)
                smt["Resource"] = cache
        return policy