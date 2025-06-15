from os import stat
from tools.policy_translator import PolicyTranslator
from tools.encoder import Encoder
from z3 import *
from tools.variable_replace import PolicyVariableReplacer
import copy

class Handler():

    encoder = Encoder()
    translator = PolicyTranslator()
    __actions = ['iot:Connect', 'iot:Publish', 'iot:Subscribe', 'iot:Receive']

    def check_implies(self, policy, smt):
        """
        A wrapper of Z3 implies, reverse the arguments.
        This function is very inelegant, historical legacy.
        """
        # policy >= smt
        exp = Implies(smt, policy)
        s = Solver()
        s.add(Not(exp))
        if s.check() == unsat:
            return True
        else:
            return False

    def from_expected_to_topics(self, expected):
        """
        To encode the security properties.
        """
        deny_cache = []
        allow_cache = []
        for action in expected.keys():
            if action == "ShouldNotReceive":
                contents = expected[action]
                if type(contents) == str:
                    contents = [contents]
                for content in contents:
                    deny_cache.append([content, "iot:Subscribe"])
            if action == "ShouldNotPublish":
                contents = expected[action]
                if type(contents) == str:
                    contents = [contents]
                for content in contents:
                    deny_cache.append([content, "iot:Publish"])
            if action == "Receive":
                contents = expected[action]
                if type(contents) == str:
                    contents = [contents]
                for content in contents:
                    allow_cache.append([content, "iot:Subscribe"])
            if action == "Publish":
                contents = expected[action]
                if type(contents) == str:
                    contents = [contents]
                for content in contents:
                    allow_cache.append([content, "iot:Publish"])
        return allow_cache, deny_cache

    def real_semantic_translate(self, policy, half=False, fake=False):
        """
        To encode the security properties.

        if half == True:
            see self.half_semantic_translate
        else:
            fully translate the policy to z3
        """

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
        """
        Q: What is half semantic translate?
        A: Something like naive encode, ignore the MQTT wildcards, no deep encoding.
        """
        return self.real_semantic_translate(policy, half=True)

    def make_temp_policy_from_topics(self, topics, with_action=False, full=True):
        """
        A tricky way to reduce functions, just transfer expected topics to a fake policy. (Allow)
        """
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
                    for a in self.__actions:
                        cache.append({"Action": a, "Effect": 'Allow', "Resource": t})
            else:
                if with_action:
                    a = topic[1]
                    cache.append({"Action": a, "Effect": 'Allow',"Resource": t})
                else:
                    for a in self.__actions:
                        cache.append({"Action": a, "Effect": 'Allow', "Resource": t})

        return { "Statement": cache }

    def make_temp_deny_policy_from_topics(self, topics, with_action=False, full=True):
        """
        A tricky way to reduce functions, just transfer expected topics to a fake policy. (Deny)
        """
        temp_policy = self.make_temp_policy_from_topics(topics, with_action=with_action, full=full)
        for smt in temp_policy["Statement"]:
            smt["Effect"] = "Deny"
        return temp_policy

    def make_naive_temp_policy_from_topics(self, topics):
        """
        Do nothing with action "iot:Receive"
        """
        return self.make_temp_policy_from_topics(topics, with_action=True, full=False)

    def check_intersection(self, policy1, policy2, deep=False):
        """
        Check the intersection of two policy simply
        """
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
    
    def make_separate_policies(self, policy):
        def split_resource(stmt):
            if type(stmt["Resource"]) == list:
                cache = []
                for cell in stmt["Resource"]:
                    new_stmt = {"Effect": stmt["Effect"], "Action": stmt["Action"], "Resource": cell}
                    cache.append(new_stmt)
                return cache 
            else:
                return [stmt] 
        new_policy = self.translator.deep_translate(policy)  # To make the policy simple
        connect_allows = []
        connect_denys = []
        publish_allows = []
        publish_denys = []
        subscribe_allows = []
        subscribe_denys = []
        receive_allows = []
        receive_denys = []

        for stmt in new_policy["Statement"]:
            stmt_splited = split_resource(stmt)
            for stmt in stmt_splited:
                if stmt["Action"]  == self.__actions[0]:
                    if stmt["Effect"] == "Allow":
                        connect_allows.append(stmt)
                    elif stmt["Effect"] == "Deny":
                        connect_denys.append(stmt)
                if stmt["Action"]  == self.__actions[1]:
                    if stmt["Effect"] == "Allow":
                        publish_allows.append(stmt)
                    elif stmt["Effect"] == "Deny":
                        publish_denys.append(stmt)
                if stmt["Action"]  == self.__actions[2]:
                    if stmt["Effect"] == "Allow":
                        subscribe_allows.append(stmt)
                    elif stmt["Effect"] == "Deny":
                        subscribe_denys.append(stmt)
                if stmt["Action"] == self.__actions[3]:
                    if stmt["Effect"] == "Allow":
                        receive_allows.append(stmt)
                    elif stmt["Effect"] == "Deny":
                        receive_denys.append(stmt)
            
            fake_policies_connect = []
            fake_policies_publish = []
            fake_policies_subscribe= []
            
            for con_stmt in connect_allows:
                fake_con_denys = copy.deepcopy(connect_denys)
                fake_con_denys.append(con_stmt)
                fake_policy = {'Statement': fake_con_denys}
                fake_policies_connect.append(fake_policy)

            for pub_stmt in publish_allows:
                fake_pub_denys = copy.deepcopy(publish_denys)
                fake_pub_denys.append(pub_stmt)
                fake_policy = {'Statement': fake_pub_denys}
                fake_policies_publish.append(fake_policy)
                
            for sub_stmt in subscribe_allows:
                fake_sub_denys = copy.deepcopy(subscribe_denys)
                fake_sub_denys.append(sub_stmt)
                fake_sub_denys += receive_allows
                fake_sub_denys += receive_denys
                fake_policy = {'Statement': fake_sub_denys}
                fake_policies_subscribe.append(fake_policy)

        return fake_policies_connect, fake_policies_publish, fake_policies_subscribe

    def topic_smt_extends(self, fake_topics): # extend fakepolicy
        """
        To extend IoT Synonyms
        """
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

    def infer_from_deny(self, policy):
        """
        To infer security properties from Deny
        """
        policy = self.translator.deep_translate(policy)

        if not policy:
            return None

        stmts = policy['Statement']
        stmts = list(filter(lambda stmt: stmt['Effect'] == 'Deny', stmts))
        cache = []
        for stmt in stmts:
            resource = stmt['Resource']
            for line in resource:
                if line.startswith('topic'):
                    line = line[6:]
                if stmt['Action'] == "iot:Receive":
                    cache.append([line, 'iot:Subscribe'])
                else:
                    cache.append([line, stmt['Action']])
        cache = list(map(tuple, cache))
        cache = set(cache)
        cache = list(map(list,cache))
        # print(cache)
        return cache

    def get_policy_subscribe_allow_topics(self, policy, action_number = 2):
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
    def get_policy_connect_allow_clientids(self, policy):
        return self.get_policy_subscribe_allow_topics(policy, action_number = 0)
    def get_policy_publish_allow_topics(self, policy):
        return self.get_policy_subscribe_allow_topics(policy, action_number = 1)
    def get_policy_receive_allow_topics(self, policy):
        return self.get_policy_subscribe_allow_topics(policy, action_number = 3)

    # The Following functions are the entries.

    # -- family/User Intersection --
    def check_complete_intersection_with_topics(self, policy, topics, with_action=False):
        """
        Check 1
        """

        policy = self.translator.deep_translate(policy)
        policy_naive_SMT = self.encoder.naive_encode(policy)
        policy_SMT, policy_receive_condition = self.real_semantic_translate(policy)
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
                for a in self.__actions:
                    cache.append({"Action": a, "Effect": 'Allow', "Resource": t})
                fake_policy = { 'Statement': cache }

            # This line may be useless, keep it for now

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
        if result:
            return {"err_type": 1, "err_message": "Permission(s) is/are not excluded completely", "result": result}
        return {"err_type": 0}
    
    def check_complete_intersection_with_topics_separately(self, policy, topics, with_action=False):    


        self.replace_connect(policy)
        # Sometimes we need to get all allow statements seprately, so we need to make not only one smt model
        new_policy = self.translator.deep_translate(policy)  # To make the policy simple
   
        _, fake_policies_publish, fake_policies_subscribe = self.make_separate_policies(new_policy)
        
        result = []

        for policy in fake_policies_publish:
            publish_topics = list(filter(lambda x: x[1] == "iot:Publish", topics))
            r = self.check_complete_intersection_with_topics(policy, publish_topics, with_action=True)
            if r["err_type"] == 1:
                result.append([policy, {"ShouldNotPublish": r["result"]}])

        for policy in fake_policies_subscribe:
            subscribe_topics = list(filter(lambda x: x[1] == "iot:Subscribe", topics))
            r = self.check_complete_intersection_with_topics(policy, subscribe_topics, with_action=True)
            if r["err_type"] == 1:
                result.append([policy, {"ShouldNotReceive": r["result"]}])
        if result:
            return {"err_type": 1, "err_message": 'Permission(s) is/are not excluded completely', "result": result}
        else:
            return {"err_type": 0}

    # Outdated Function
    def check_complete_intersection_with_policy(self, policy1, policy2):
        """
        Check2: To check complete intersection between two policies.
        """
        # New Algorithm
        # Will Return intersection, and intersection_datailed (intersection from policy1 and policy2)
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

        intersection = list(set(intersection1 + intersection2))
        intersection_detailed = list(set(intersection_detailed))
        if (not intersection) and not (intersection_detailed):
            return {"err_type": 0, "result": []}
        else:
            return {"err_type": 1, "result": intersection}

    def check_complete_intersection_with_policy_cell(self, policy1, policy2):
        """
        Check 3 : To check complete intersection between two policies.
                  Can only be called by the separate function 'check_complete_intersection_with_policy_separately', because
                  no api support for now, just return true or false.
                  For a new algorithm to be faster.
        """
        # New Algorithm
        policy1 = self.translator.deep_translate(policy1)
        policy2 = self.translator.deep_translate(policy2)
        policy1_real_SMT, policy1_receive_condition = self.real_semantic_translate(policy1)
        policy2_real_SMT, policy2_receive_condition = self.real_semantic_translate(policy2)

        policy1_subscribe_allow_topics, policy1_subscribe_deny_topics = self.get_policy_subscribe_allow_topics(policy1) 
        policy2_subscribe_allow_topics, policy2_subscribe_deny_topics = self.get_policy_subscribe_allow_topics(policy2) 

        policy1_receive_allow_topics, policy1_receive_deny_topics = self.get_policy_receive_allow_topics(policy1) 
        policy2_receive_allow_topics, policy2_receive_deny_topics = self.get_policy_receive_allow_topics(policy2) 
    
        policy1_naive_SMT = self.encoder.naive_encode(policy1)
        policy2_naive_SMT = self.encoder.naive_encode(policy2)
        policy1_naive_SMT = simplify(policy1_naive_SMT)
        policy2_naive_SMT = simplify(policy2_naive_SMT)

        result = False

        if self.check_intersection(policy1_real_SMT, policy2_real_SMT):
            return True
        else:
            if not policy1_subscribe_allow_topics and not policy1_subscribe_deny_topics:
                return False
            if not policy2_subscribe_allow_topics and not policy2_subscribe_deny_topics:
                return False
            else:
                # For only one subscribe topic
                policy1_fake_subscribe_policy = self.make_naive_temp_policy_from_topics(policy1_subscribe_allow_topics)
                policy1_fake_subscribe_policy["Statement"].append({"Action": self.__actions[3], "Effect": 'Allow',"Resource": "*"})

                policy1_fake_subscribe_deny_policy = self.make_naive_temp_policy_from_topics(policy1_subscribe_deny_topics)
                policy1_fake_subscribe_deny_policy["Statement"].append({"Action": self.__actions[3], "Effect": 'Allow',"Resource": "*"})

                policy1_fake_subscribe_policy_smt = self.real_semantic_translate(policy1_fake_subscribe_policy)[0]
                policy1_fake_subscribe_deny_policy_smt = self.real_semantic_translate(policy1_fake_subscribe_deny_policy)[0]

                # If policy1's allow is completely different from policy2's deny, then we can bypass the extends
                policy2_fake_subscribe_policy = self.make_naive_temp_policy_from_topics(policy2_subscribe_allow_topics)
                policy2_fake_subscribe_policy["Statement"].append({"Action": self.__actions[3], "Effect": 'Allow',"Resource": "*"})

                policy2_fake_subscribe_deny_policy = self.make_naive_temp_policy_from_topics(policy2_subscribe_deny_topics)
                policy2_fake_subscribe_deny_policy["Statement"].append({"Action": self.__actions[3], "Effect": 'Allow',"Resource": "*"})

                policy2_fake_subscribe_policy_smt = self.real_semantic_translate(policy2_fake_subscribe_policy)[0]          
                policy2_fake_subscribe_deny_policy_smt = self.real_semantic_translate(policy2_fake_subscribe_deny_policy)[0]

                if not self.check_intersection(policy1_fake_subscribe_policy_smt, policy2_fake_subscribe_deny_policy_smt):
                    result = False
                else:
                    policy1_synonyms = self.topic_smt_extends(policy1_subscribe_allow_topics)
                    policy1_synonyms_topics = list(map(lambda x: 'topic/' + x, policy1_synonyms))
                    policy1_synonyms_topics = list(map(lambda x: [x, self.__actions[2]], policy1_synonyms_topics))
                    print(len(policy1_synonyms_topics))
                    for mqtt_topic in policy1_synonyms_topics:
                        mqtt_topic = mqtt_topic[0]
                        fake_policy = self.make_naive_temp_policy_from_topics([mqtt_topic])
                        fake_policy_naive = copy.deepcopy(fake_policy)
                        if policy1_subscribe_deny_topics:
                            fake_policy["Statement"].append({"Action": self.__actions[2], "Effect": 'Allow',"Resource": policy1_subscribe_deny_topics})
                        if policy1_receive_allow_topics:
                            fake_policy["Statement"].append({"Action": self.__actions[3], "Effect": 'Allow',"Resource": policy1_receive_allow_topics})
                        if policy1_receive_deny_topics:
                            fake_policy["Statement"].append({"Action": self.__actions[3], "Effect": 'Deny',"Resource": policy1_receive_deny_topics})
                        fake_policy_naive = self.translator.deep_translate(fake_policy_naive)
                        fake_policy_naive_SMT = self.encoder.naive_encode(fake_policy_naive)

                        fake_policy_naive_SMT = simplify(fake_policy_naive_SMT)
                        if self.check_intersection(policy1_naive_SMT, fake_policy_naive_SMT) and self.check(fake_policy_naive_SMT): #and self.check_intersection(fake_policy_SMT, policy2_real_SMT):
                            return True

                #------------#

                if not self.check_intersection(policy2_fake_subscribe_policy_smt, policy1_fake_subscribe_deny_policy_smt):

                    result = False
                else:
                    policy2_synonyms = self.topic_smt_extends(policy2_subscribe_allow_topics)
                    policy2_synonyms_topics = list(map(lambda x: 'topic/' + x, policy2_synonyms))
                    policy2_synonyms_topics = list(map(lambda x: [x, self.__actions[2]], policy2_synonyms_topics))
                    for mqtt_topic in policy2_synonyms_topics:
                        mqtt_topic = mqtt_topic[0]
                        print(mqtt_topic)
                        fake_policy = self.make_naive_temp_policy_from_topics([mqtt_topic])
                        fake_policy_naive = copy.deepcopy(fake_policy)
                        if policy2_subscribe_deny_topics:
                            fake_policy["Statement"].append({"Action": self.__actions[2], "Effect": 'Deny',"Resource": policy2_subscribe_deny_topics})
                        if policy2_receive_allow_topics: 
                            fake_policy["Statement"].append({"Action": self.__actions[3], "Effect": 'Allow',"Resource": policy2_receive_allow_topics})
                        if policy2_receive_deny_topics:
                            fake_policy["Statement"].append({"Action": self.__actions[3], "Effect": 'Deny',"Resource": policy2_receive_deny_topics})
                        fake_policy_naive = self.translator.deep_translate(fake_policy_naive)
                        fake_policy_naive_SMT = self.encoder.naive_encode(fake_policy_naive)
                        fake_policy_naive_SMT = simplify(fake_policy_naive_SMT)
                        if self.check_intersection(policy2_naive_SMT, fake_policy_naive_SMT) and self.check(fake_policy_naive_SMT): #and self.check_intersection(fake_policy_SMT, policy2_real_SMT):
                            return True
        return result

    def check_complete_intersection_with_policy_separately(self, policy1, policy2):
        self.replace_connect(policy1)
        self.replace_connect(policy2)

        policy1 = self.remove_useless_deny(policy1)
        policy2 = self.remove_useless_deny(policy2)
        fake_policy1_connects, fake_policy1_publishes, fake_policy1_subscribes = self.make_separate_policies(policy1)
        fake_policy2_connects, fake_policy2_publishes, fake_policy2_subscribes = self.make_separate_policies(policy2)
        results = []

        for i in range(len(fake_policy1_connects)):
            for j in range(len(fake_policy2_connects)):
                intersection = self.check_complete_intersection_with_policy_cell(fake_policy1_connects[i], fake_policy2_connects[j])
                if intersection:
                    results.append([fake_policy1_connects[i], fake_policy2_connects[j]])

        for i in range(len(fake_policy1_publishes)):
            for j in range(len(fake_policy2_publishes)):
                intersection = self.check_complete_intersection_with_policy_cell(fake_policy1_publishes[i], fake_policy2_publishes[j])
                if intersection:
                    results.append([fake_policy1_publishes[i], fake_policy2_publishes[j]])
        for i in range(len(fake_policy1_subscribes)):
            for j in range(len(fake_policy2_subscribes)):
                intersection = self.check_complete_intersection_with_policy_cell(fake_policy1_subscribes[i], fake_policy2_subscribes[j])
                if intersection:
                    results.append([fake_policy1_subscribes[i], fake_policy2_subscribes[j]])
        if results:
            result = {"err_type": 1, "err_message": "Intersection between the two policy", "result": results}
        else:
            result = {"err_type": 0}
        return result

    def check_complete_expected_with_topics(self, policy, allow_topics, deny_topics):

        """
        Check 4 (addon): check if a policy is completely same as what security properties want.
        """
        # check if the policy is equal to expected. Note: will check deny intersection first
        def check_implies(policy, smt):
            exp = Implies(smt, policy)
            s = Solver()
            s.add(Not(exp))
            if s.check() == unsat:
                return True
            else:
                return False
        policy = self.translator.deep_translate(policy)
        result_deny = None
        if deny_topics:
            result_deny = self.check_complete_intersection_with_topics(policy, deny_topics, with_action=True)
        if result_deny:
            return {"err_type": 1, "err_message": "Intersection with Deny Statements", "result": result_deny}
        else:
            allow_policy = self.make_temp_policy_from_topics(allow_topics, with_action=True)
            if deny_topics:
                deny_policy = self.make_temp_deny_policy_from_topics(deny_topics, with_action=True)
                fake_policy = {"Statement": allow_policy["Statement"] + deny_policy["Statement"]}
                topic_policy_SMT = self.real_semantic_translate(fake_policy, fake=True)[0]
            else:
                fake_policy = allow_policy
                topic_policy_SMT = self.real_semantic_translate(fake_policy, fake=True)[0]

            policy_SMT = self.real_semantic_translate(policy)[0]
            result = check_implies(policy_SMT, topic_policy_SMT)
            if result:
                expression = And(Not(topic_policy_SMT), policy_SMT)
                s = Solver()
                s.add(expression)
                if s.check() == sat:
                    print("Overpriviledged!!")
                    m = s.model()
                    resource = String("Resource")
                    action = String("Action")
                    return {"err_type": 2, "err_msg": "Overprivileged", "result": {"CounterExample": {"Action": str(m[action]).strip(' " '), "Resource": str(m[resource]).strip(' " ')}}}
                else:
                    return {"err_type": 0}

            else:
                intersection = self.check_intersection(policy_SMT, topic_policy_SMT)
                if intersection:
                    return {"err_type": 3, "err_message": "Deny well, but overlap", "result": True}
                else:
                    return {"err_type": 4, "err_message": "Deny well ,but inconsistent", "result": True}

    # Check if the policy is overly permissive than another - check2
    def check_overly_permissive_with_policy(self, policy, policy2):

        """
        Check 3: To check if a policy is more permissive than policy2
        """

        policy = self.remove_useless_deny(policy)
        policy2 = self.remove_useless_deny(policy2)

        policy = self.translator.deep_translate(policy)
        policy2 = self.translator.deep_translate(policy2)
        policy_smt = self.real_semantic_translate(policy)[0]
        policy2_smt = self.real_semantic_translate(policy2)[0]
        result = self.check_implies(policy_smt, policy2_smt)
        if result:
            expression = And(Not(policy2_smt), policy_smt)
            s = Solver()
            s.add(expression)
            if s.check() == sat:
                m = s.model()
                resource = String("Resource")
                action = String("Action")
                return {"err_type": 2, "err_msg": "Overprivileged", "result": {"CounterExample": {"Action": str(m[action]).strip(' " '), "Resource": str(m[resource]).strip(' " ')}}}
            else:
                return {"err_type": 0}
        else:
            return {"err_type": 0}


    def check_infer_policy(self, policy):

        """
        Addon Check: To check if the deny statements are working.
        """
        intered_topics = self.infer_from_deny(policy)
        return self.check_complete_intersection_with_topics_separately(policy, intered_topics, with_action=True)
    
    def remove_useless_deny(self, policy):
        policy = self.translator.deep_translate(policy)
        deny_result = self.check_infer_policy(policy)
        if deny_result["err_type"] == 0:
            return policy

        result = deny_result["result"]
        result = map(lambda x: x[0], result)
        result = map(lambda x: x["Statement"], result)
        cache = []
        for r in result:
            r = filter(lambda x: x["Effect"] == "Deny" and x["Action"] == self.__actions[2], r)
            r = map(lambda x: x["Resource"], r)
            r = list(r)
            cache += r
        result = cache

        new_policy = {"Statement": []}
        for stmt in policy["Statement"]:
            # To delete the Deny statement if it can be 
            if stmt["Effect"] == "Deny" and stmt["Action"] == self.__actions[2]:
                new_stmt = {"Effect": "Deny", "Action": self.__actions[2], "Resource": []}
                for r in stmt["Resource"]:
                    if not r in result:
                        new_stmt["Resource"].append(r)
                new_policy["Statement"].append(new_stmt)
            else:
                new_policy["Statement"].append(stmt)

        new_policy["Statement"] = list(filter(lambda x: x["Resource"], new_policy["Statement"]))
        return new_policy

    def replace_connect(self, policy):
        connect_replacer = PolicyVariableReplacer()
        return connect_replacer.replace(policy)
        

    def check_connect(self, policy):
        policy = copy.deepcopy(policy)
        if self.replace_connect(policy):
            return {"err_type": 3, "err_message": "Client Id is open"}
        else:
            return {"err_type": 0}
        


    def check_publish_subscribe_relation(self, policy):
        """
        Check5
        """
        
        publish_statements = [
            stmt for stmt in policy["Statement"]
            if stmt["Action"] == "iot:Publish"
        ]
        subscribe_statements = [
            stmt for stmt in policy["Statement"]
            if stmt["Action"] == "iot:Subscribe"
        ]

        results = []

        for pub_stmt in publish_statements:
            for sub_stmt in subscribe_statements:
                temp_policy = {"Statement": [pub_stmt, sub_stmt]}
                smt = self.encoder.deep_encode_with_uuid(temp_policy)
                s = Solver()
                s.add(smt)
                if s.check() == sat:
                    m = s.model()
                    results.append({
                        "Action": str(m[String("Action")]),
                        "Resource": str(m[String("Resource")])
                    })

        if results:
            return {
                "err_type": 1,
                "err_message": "Publish and Subscribe permissions overlap (SMT verified)",
                "result": results
            }
        else:
            return {
                "err_type": 0
            }