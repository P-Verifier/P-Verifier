

from os import stat
from tools.policy_translator import PolicyTranslator 
from tools.encoder import Encoder
from z3 import *
import copy

class Handler():
    
    encoder = Encoder()
    translator = PolicyTranslator()
    __actions = ['iot:Connect', 'iot:Publish', 'iot:Subscribe', 'iot:Receive']
        
    def real_semantic_translate(self, policy, half=False, fake=False):
        
        # Get the real semantics of a Policy directly available, only * replace with wildcard incomplete 
        # Receive Condition will be Outside
        def check_exist(smt, policy_smt):
            s = Solver()
            s.add(And(smt, policy_smt))
            if s.check() == sat:
                return True
            else:
                return False

        def subscribe2receive(smt):
            smt["Action"] = self.__actions[2]
            return smt
 
            
        # new_policy = self.translator.subscribe_translate(policy) 

        new_policy = self.translator.deep_translate(policy) 
        policy_naive_smt = self.encoder.naive_encode(new_policy)

        # Split each action
        connects = []
        publishs = []
        subscribes = []
        receives = []

        for smt in new_policy["Statement"]:
            if smt["Action"]  == self.__actions[0]:
                connects.append(smt)
            if smt["Action"]  == self.__actions[1]:
                publishs.append(smt)
            if smt["Action"]  == self.__actions[2]:
                subscribes.append(smt)
            if smt["Action"] == self.__actions[3]:
                receives.append(smt)
        
        ### Check if the MQTT wildcard is Deny off, the ones that are not will form Deep Cache
        
        deep_cache = []
        for smt in subscribes:
            if smt['Effect'] == 'Allow':
                resources = smt["Resource"]
                if type(resources) == str:
                    resources = [resources]
                for resource in resources:
                    if ("+" in resource or "#" in resource):
                        cell = {
                            "Effect": smt["Effect"],
                            "Action": smt["Action"],
                            "Resource": resource
                        }
                        smt_smt = self.encoder.naive_encode_single(cell)
                        exists = check_exist(smt_smt, policy_naive_smt)
                        if exists:
                            deep_cache.append(self.encoder.deep_encode_single(cell))
        
                            
        ### Receive will change to subscribe###
        res_subs = list(map(subscribe2receive, receives))
        # print(res_subs)

        ### connect and publish ###
        fake_new_policy = {"Statement": connects + publishs}
        fake_subs = { "Statement" : subscribes}
        fake_res_subs = {"Statement": res_subs}
        ### Encode differents actions
        start = self.encoder.naive_encode(fake_new_policy) # Initial SMT Encode
        subscribes_start = self.encoder.naive_encode(fake_subs) # Initial subscribe
        if not fake:
            receive_condition = self.encoder.naive_encode(fake_res_subs) # Receive as condition of Subscribe
        else:
            receive_condition = self.encoder.deep_encode(fake_res_subs) # Receive as condition of Subscribe
        # The case of treating wildcards as characters cannot be encoded as wildcards
        if not half:
            subscribe_mqtt_wildcards = Or(deep_cache) # extend to origin policy
            ### Merge to get the correct semantics of the final Policy (including the semantics of the MQTT wildcard)
            result = Or(start, And(receive_condition, Or(subscribes_start, subscribe_mqtt_wildcards)))
        else:
            ### Here the Receive is only encoded as a condition, the MQTT wildcard is still a character, and there is no deep encoding
            result = Or(start, And(receive_condition, subscribes_start))

        return result, receive_condition

    def half_semantic_translate(self, policy):
        return self.real_semantic_translate(policy, half=True)

    def make_temp_policy_from_topics(self, topics, with_action=False, full=True):
        # with_action: action details
        # topic: "hello/world" / "topic/hello/world"
        # topic: ["hello/world", 'iot:Subscribe'] with_action=True

        cache = []
        for topic in topics:
            t = None
            a = None
            if type(topic) == list:
                t = topic[0]
            else:
                t = topic
            t = t.replace("{any}", '+')
            if not t.startswith("topic/"):
                t = 'topic/' + t
            if full:
                if with_action:
                    a = topic[1]
                    cache.append({"Action": a, "Effect": 'Allow',"Resource": t})
                    if a == self.__actions[2]:
                        cache.append({"Action": self.__actions[3], "Effect": 'Allow',"Resource": t})
                else:
                    for a in self.__actions[1:]:
                        cache.append({"Action": a, "Effect": 'Allow', "Resource": t})
            else:
                if with_action:
                    a = topic[1]
                    cache.append({"Action": a, "Effect": 'Allow',"Resource": t})

        return { "Statement": cache }
    
    def make_temp_deny_policy_from_topics(self, topics, with_action=False, full=True):
        temp_policy = self.make_temp_policy_from_topics(topics, with_action=with_action, full=full)
        for smt in temp_policy["Statement"]:
            smt["Effect"] = "Deny"
        return temp_policy

    def make_naive_temp_policy_from_topics(self, topics):
        return self.make_temp_policy_from_topics(topics, with_action=True, full=False)

    def check_intersection(self, policy1, policy2, deep=False):
        # Simple Intersection
        # if deep == True will be slow to get details.
        action = String('Action')
        resource = String('Resource')
        result = z3.And(policy1, policy2)
        s = Solver()
        s.add(result)

        if not deep:
            if s.check() == sat:
                return True
            else:
                return False
        else:
            cache = []
            while s.check() == sat:
                s_result = s.model()
                cache.append(s_result)
                s.add(z3.Or(And(action != s_result[action], resource != s_result[action])))
            return cache

    def check_implies(self, policy, smt):
        exp = Implies(smt, policy)
        s = Solver()
        s.add(Not(exp))
        if s.check() == unsat:
            return True
        else:
            return False

    def topic_smt_extends(self, fake_topics): # extend fakepolicy 
            
            def get_sub_set(nums):
                sub_sets = [[]]
                for x in nums:
                    sub_sets.extend([item + [x] for item in sub_sets])
                return sub_sets 

            def extend_topic(topic):
                if topic.startswith("topic/"):
                    topic = topic[6:]
                topic = topic.split("/")
                sets = range(len(topic))
                sub_sets = get_sub_set(sets)
                cache = []
                for sub in sub_sets:
                    topic_cache = copy.deepcopy(topic)
                    for point in sub:
                        topic_cache[point] = "+"
                    cache.append("/".join(topic_cache))
                
                slash_sets = copy.deepcopy(cache)
                slash_sets = map(lambda x: x.split("/"), slash_sets)
                slash_sets = list(slash_sets)
                slash_cache = set()
                for i in sets:
                    for cell in slash_sets:
                        new_cell = copy.deepcopy(cell)
                        new_cell[i] = '#'
                        slash_cache.add("/".join(new_cell))

                for cell in slash_cache:
                    cell = cell[0: cell.index("#") + 1]
                    cache.append(cell)
                return cache
            if type(fake_topics) == str:
                fake_topics = [fake_topics]
            subscribe_topics = []
            for topic in fake_topics:
                if type(topic) == list:
                    if topic[1] == self.__actions[2]:
                        subscribe_topics.append(topic[0])
                else:
                    subscribe_topics.append(topic)
            e_topics = []
            for topic in subscribe_topics:
                cache = extend_topic(topic)
                e_topics = e_topics + cache
            e_topics = list(set(e_topics))
            return e_topics

    def get_policy_length(self, policy):
        # get a policy，subscribe action allow/deny topic max length
        policy = self.translator.deep_translate(policy)
        allow_max = 0
        deny_max = 0
        for smt in policy["Statement"]:
            if smt["Action"] == self.__actions[2]:
                for resource in smt['Resource']:
                    length = resource.count('/') + 1
                    if smt["Effect"] == 'Allow':
                        allow_max = length if length > allow_max else allow_max
                    if smt["Effect"] == 'Deny':
                        deny_max = length if length > deny_max else deny_max
        return allow_max, deny_max
    
    def get_policy_subscribe_allow_topics(self, policy, action_number=2):
        # get a policy，subscribe action allow/deny topic
        policy = self.translator.deep_translate(policy)
        allow_topics = []
        deny_topics = []
        for smt in policy["Statement"]:
            if smt["Action"] == self.__actions[action_number]: # action_number default 2
                if smt["Effect"] == 'Allow':
                    for resource in smt['Resource']:
                        allow_topics.append(resource)
                if smt["Effect"] == 'Deny':
                    for resource in smt['Resource']:
                        deny_topics.append(resource)
        return allow_topics, deny_topics

    def get_policy_publish_allow_topics(self, policy):
        return self.get_policy_subscribe_allow_topics(policy, action_number=1)
    def get_policy_receive_allow_topics(self, policy):
        return self.get_policy_subscribe_allow_topics(policy, action_number=3)
        
        
    # -- family/User Intersection --
    def check_complete_intersection_with_topics(self, policy, topics, with_action=False):

        policy = self.translator.deep_translate(policy)
        policy_naive_SMT = self.encoder.naive_encode(policy)
        policy_SMT, policy_receive_condition = self.real_semantic_translate(policy)
        # policy_Naive_SMT, topics_receive_condition = self.half_semantic_translate(policy)
        result = []
        
        for topic in topics:
            if type(topic) == list:
                t = topic[0]
                with_action = True
            else:
                t = topic
            t.replace('{any}', '+')
            if not t.startswith("topic/"):
                t = 'topic/' + t
            if with_action:
                a = topic[1]
                fake_policy = {'Statement':[{"Action": a, "Effect": 'Allow',"Resource": t}]}
                if a == self.__actions[2]:
                    fake_policy['Statement'].append({"Action": self.__actions[3], "Effect": 'Allow', "Resource": t}) 
            else:
                cache = []
                for a in self.__actions[1:]:
                    cache.append({"Action": a, "Effect": 'Allow', "Resource": t})
                fake_policy = { 'Statement': cache }
            
            fake_policy_subscribes = list(filter(lambda x: x["Action"] == self.__actions[2], fake_policy["Statement"]))
            fake_policy_smt = self.real_semantic_translate(fake_policy)[0]
            
            if self.check_intersection(policy_SMT, fake_policy_smt):
                result.append(topic)
            elif (with_action and topic[1] == self.__actions[2]) or not with_action:
                if not self.check_intersection(policy_receive_condition, fake_policy_smt):
                    continue
                new_subscribe_topics = self.topic_smt_extends([topic])
                new_subscribe_topics_subscribe = list(map(lambda x: [x, self.__actions[2]], new_subscribe_topics))
                new_subscribe_topics_subscribe = list(map(lambda x: 'topic/' + x[0], new_subscribe_topics_subscribe))

                for t in new_subscribe_topics_subscribe:
                    fake_policy = {'Statement':[{"Action": self.__actions[2], "Effect": 'Allow',"Resource": t}]}
                    fake_policy_smt = self.encoder.naive_encode(fake_policy)
                    if self.check_intersection(policy_naive_SMT, fake_policy_smt):
                        result.append([topic[0], self.__actions[2]])
                        break
        return result

    def check_complete_intersection_with_policy(self, policy1, policy2):
        # New Algorithm
        policy1 = self.translator.deep_translate(policy1)
        policy2 = self.translator.deep_translate(policy2)
        policy1_naive_SMT = self.encoder.naive_encode(policy1)
        policy2_naive_SMT = self.encoder.naive_encode(policy2)
        policy1_real_SMT, policy1_receive_condition = self.real_semantic_translate(policy1)
        policy2_real_SMT, policy2_receive_condition = self.real_semantic_translate(policy2)

        policy1_subscribe_allow_topics, policy1_subscribe_deny_topics = self.get_policy_subscribe_allow_topics(policy1)
        policy2_subscribe_allow_topics, policy2_subscribe_deny_topics = self.get_policy_subscribe_allow_topics(policy2)

        policy1_receive_allow_topics, policy1_receive_deny_topics = self.get_policy_receive_allow_topics(policy1)
        policy2_receive_allow_topics, policy2_receive_deny_topics = self.get_policy_receive_allow_topics(policy2)

        ### get publish topics
        policy1_publish_allow_topics, policy1_publish_deny_topics = self.get_policy_publish_allow_topics(policy1)
        policy2_publish_allow_topics, policy2_publish_deny_topics = self.get_policy_publish_allow_topics(policy2)

        intersection1 = []
        intersection2 = []
        intersection_detailed = []
        for topic in policy2_publish_allow_topics:
            fake_policy = {'Statement':[{"Action": self.__actions[1], "Effect": 'Allow',"Resource": topic}]} 
            if policy2_publish_deny_topics:
                fake_policy['Statement'].append({"Action": self.__actions[1], "Effect": 'Deny',"Resource": policy2_publish_deny_topics})
            fake_policy_SMT = self.half_semantic_translate(fake_policy)[0]
            if self.check_intersection(policy1_real_SMT, fake_policy_SMT):
                intersection2.append((topic, self.__actions[1]))
                intersection_detailed.append((topic, self.__actions[1]))
        
        ### split Policy1，solve Policy2
        for topic in policy1_publish_allow_topics:
            fake_policy = {'Statement':[{"Action": self.__actions[1], "Effect": 'Allow',"Resource": topic}]} 
            if policy1_publish_deny_topics:
                fake_policy['Statement'].append({"Action": self.__actions[1], "Effect": 'Deny',"Resource": policy1_publish_deny_topics})
            fake_policy_SMT = self.half_semantic_translate(fake_policy)[0]
            if self.check_intersection(policy2_real_SMT, fake_policy_SMT):
                intersection1.append((topic, self.__actions[1]))
                intersection_detailed.append((topic, self.__actions[1]))
        
        for topic in policy2_subscribe_allow_topics:
            fake_policy = {'Statement':[{"Action": self.__actions[2], "Effect": 'Allow',"Resource": topic}]} 
            if policy2_subscribe_deny_topics:
                fake_policy['Statement'].append({"Action": self.__actions[2], "Effect": 'Deny',"Resource": policy2_subscribe_deny_topics})
            if policy2_receive_allow_topics:
                fake_policy['Statement'].append({"Action": self.__actions[3], "Effect": 'Allow',"Resource": policy2_receive_allow_topics})
            if policy2_receive_deny_topics:
                fake_policy['Statement'].append({"Action": self.__actions[3], "Effect": 'Deny',"Resource": policy2_receive_deny_topics})

            fake_policy_SMT = self.real_semantic_translate(fake_policy)[0]
            if self.check_intersection(policy1_real_SMT, fake_policy_SMT):
                intersection2.append((topic, self.__actions[2]))
                intersection_detailed.append((topic, self.__actions[2]))
            else:
                if not self.check_intersection(policy1_receive_condition, fake_policy_SMT):
                    continue
                else:
                    new_subscribe_topics = self.topic_smt_extends([topic])
                    new_subscribe_topics_subscribe = list(map(lambda x: 'topic/' + x, new_subscribe_topics))
                    new_subscribe_topics_subscribe = list(map(lambda x: [x, self.__actions[2]], new_subscribe_topics_subscribe))
                    for mqtt_topic in new_subscribe_topics_subscribe:
                        fake_policy = self.make_naive_temp_policy_from_topics([mqtt_topic])
                        fake_policy_naive = copy.deepcopy(fake_policy)
                        fake_policy["Statement"].append({"Action": self.__actions[3], "Effect": 'Allow',"Resource": policy2_receive_allow_topics})
                        fake_policy["Statement"].append({"Action": self.__actions[3], "Effect": 'Deny',"Resource": policy2_receive_deny_topics})
                        fake_policy_SMT = self.real_semantic_translate(fake_policy)[0]
                        fake_policy_naive_SMT = self.encoder.naive_encode(fake_policy_naive)
                        if not self.check_implies(policy1_naive_SMT, fake_policy_naive_SMT):
                            continue
                        if self.check_intersection(fake_policy_SMT, policy1_real_SMT):
                            intersection_detailed.append(tuple(mqtt_topic))
                            intersection2.append((topic, self.__actions[2]))

        for topic in policy1_subscribe_allow_topics:
            fake_policy = {'Statement':[{"Action": self.__actions[2], "Effect": 'Allow',"Resource": topic}]} 
            if policy1_subscribe_deny_topics:
                fake_policy['Statement'].append({"Action": self.__actions[2], "Effect": 'Deny',"Resource": policy1_subscribe_deny_topics})
            if policy1_receive_allow_topics:
                fake_policy['Statement'].append({"Action": self.__actions[3], "Effect": 'Allow',"Resource": policy1_receive_allow_topics})
            if policy1_receive_deny_topics:
                fake_policy['Statement'].append({"Action": self.__actions[3], "Effect": 'Deny',"Resource": policy1_receive_deny_topics})

            fake_policy_SMT = self.real_semantic_translate(fake_policy)[0]
            if self.check_intersection(policy2_real_SMT, fake_policy_SMT):
                intersection1.append((topic, self.__actions[2]))
                intersection_detailed.append((topic, self.__actions[2]))
            else:
                if not self.check_intersection(policy2_receive_condition, fake_policy_SMT):
                    continue
                else:
                    new_subscribe_topics = self.topic_smt_extends([topic])
                    new_subscribe_topics_subscribe = list(map(lambda x: 'topic/' + x, new_subscribe_topics))
                    new_subscribe_topics_subscribe = list(map(lambda x: [x, self.__actions[2]], new_subscribe_topics_subscribe))
                    for mqtt_topic in new_subscribe_topics_subscribe:
                        fake_policy = self.make_naive_temp_policy_from_topics([mqtt_topic])
                        fake_policy_naive = copy.deepcopy(fake_policy)
                        fake_policy["Statement"].append({"Action": self.__actions[3], "Effect": 'Allow',"Resource": policy1_receive_allow_topics})
                        fake_policy["Statement"].append({"Action": self.__actions[3], "Effect": 'Deny',"Resource": policy1_receive_deny_topics})
                        fake_policy_SMT = self.real_semantic_translate(fake_policy)[0]
                        fake_policy_naive_SMT = self.encoder.naive_encode(fake_policy_naive)
                        if not self.check_implies(policy2_naive_SMT, fake_policy_naive_SMT):
                            continue
                        if self.check_intersection(fake_policy_SMT, policy2_real_SMT):
                            intersection_detailed.append(tuple(mqtt_topic))
                            intersection1.append((topic, self.__actions[2]))

        # return list(set(intersection1)), list(set(intersection2))
        intersection = list(set(intersection1 + intersection2))
        intersection_detailed = list(set(intersection_detailed))
        if (not intersection) and not (intersection_detailed):
            return False
        return intersection, intersection_detailed


    def check_complete_expected_with_topics(self, policy, allow_topics, deny_topics):
        # check if the policy is equal to expected. Note: will check deny intersection first
        
        def check_implies(policy, smt):
            exp = Implies(smt, policy)
            s = Solver()
            s.add(Not(exp))
            if s.check() == unsat:
                return True
            else:
                print(s.model())
                return False
        policy = self.translator.deep_translate(policy)
        result_deny = None
        if deny_topics:
            result_deny = self.check_complete_intersection_with_topics(policy, deny_topics, with_action=True)
        if result_deny:
            print("Intersection!")
            for line in result_deny:
                print(line)
            return True
        else:
            allow_policy = self.make_temp_policy_from_topics(allow_topics, with_action=True) 
            # allow_policy_SMT = self.real_semantic_translate(allow_policy)[0]
            # allow_policy_SMT = self.real_semantic_translate(allow_policy, fake=True)[0]
            if deny_topics:  
                deny_policy = self.make_temp_deny_policy_from_topics(deny_topics, with_action=True)

                fake_policy = {"Statement": allow_policy["Statement"] + deny_policy["Statement"]}
                topic_policy_SMT = self.real_semantic_translate(fake_policy, fake=True)[0]
            else:
                fake_policy = allow_policy
                topic_policy_SMT = self.real_semantic_translate(fake_policy, fake=True)[0]

            policy_SMT = self.real_semantic_translate(policy)[0]
            # print(policy_SMT)
            result = check_implies(policy_SMT, topic_policy_SMT)
            if result:
                expression = And(Not(topic_policy_SMT), policy_SMT)
                # print(simplify(topic_policy_SMT))
                s = Solver()
                s.add(expression)
                if s.check() == sat:
                    print("Overprivileged！！")
                    return s.model() 
                else:
                    print("Good!!")
                    return False
            else:
                if self.check_intersection(policy_SMT, topic_policy_SMT):
                    print("Policy permissions do not meet expectations, but overlap")
                    return True
                else:
                    print("Policy is completely inconsistent with expectations")
                    return True
                
