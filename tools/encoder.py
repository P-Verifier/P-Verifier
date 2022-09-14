from z3 import *

class Encoder:

    """
       This Encoder should be used together with translater, 
       our core idea is not to use Z3 when we can, 
       so we don't differentiate between actions in the encode class for now.
    """

    actions = ['iot:Connect', 'iot:Publish', 'iot:Subscribe', 'iot:Receive']
    __regular_full_set = None
    __regular_plus_set = None
    __regular_mqtt_set = None


    def __init__(self):
        self.__regular_full_set = z3.Star(z3.Complement(z3.Re("*")))
        self.__regular_plus_set = z3.Concat(z3.Star(z3.Range('a', 'z')), z3.Star(z3.Range('A', 'Z')), z3.Star(z3.Range('0', '9')), z3.Star(z3.Re("$")), z3.Star(z3.Re("{")), z3.Star(z3.Re("}")), z3.Star(z3.Re(":")), z3.Star(z3.Re("+")))
        self.__regular_mqtt_set = z3.Concat(z3.Star(Re('+')), z3.Star(Re("+/")), z3.Star(Re('/+')))

    def __naive_re_constrains(self, string, action):
        _r = String("Resource")
        
        # assign = z3.String(action)
        if string.count('*') == 0:
            return z3.InRe(_r, z3.Re(string))
        # to point if the string starts or ends with *
        flag = [0, 0]
        if string.startswith('*'):
            string = string[1:]
            flag[0] = 1
        if string.endswith('*'):
            string = string[0:-1]
            flag[1] = 1
        string = string.split("*")
        cache = []
        for line in string:
            cache.append(z3.Re(line))
            cache.append(self.__regular_full_set)
        cache = cache[0:-1]
        if flag[0]:
            cache.insert(0, self.__regular_full_set)
        if flag[1]:
            cache.append(self.__regular_full_set)
        re_model = z3.Concat(cache)
        return z3.InRe(_r, re_model) 

    def __naive_str_constrains(self, string, action):
        # entry of resource(naive)
        _r = String("Resource")

        if "*" not in string:
            return _r == string
        else:
            return self.__naive_re_constrains(string, action)

    def __deep_re_constrains(self, string, action, effect):
        # Found MQTT Wildcards

        string_queue = []
        little_queue = []
        if string.endswith('#'):
            string = string[0:-1] + "*"
        for char in string:
            if char == "*":
                string_queue.append(Re(''.join(little_queue)))
                string_queue.append(self.__regular_full_set)
                little_queue = []
            elif char == "+":
                string_queue.append(Re(''.join(little_queue)))
                string_queue.append(self.__regular_plus_set)
                little_queue = []
            else:
                little_queue.append(char)
        if little_queue:
            string_queue.append(Re(''.join(little_queue)))

        return InRe(String("Resource"), Concat(string_queue))

    def __deep_str_constrains(self, string, action, effect):
        # entry of resource(deep)

        if effect == "Deny":
            # Deny's don't need deep because it has been pre-processed 
            return self.__naive_str_constrains(string, action)
        elif not action == self.actions[2]: # No need to deep if not a subscribe action
            return self.__naive_str_constrains(string, action)
        elif (not "+" in string) and (not "#" in string):
            return self.__naive_str_constrains(string, action)
        else:
            return self.__deep_re_constrains(string, action, effect)

    def __mqtt_str_solver(self, string, length):
        _r = String("Resource")
        
        # assign = z3.String(action)
        main_smt = None
        if string.count('*') == 0:
            main_smt = z3.InRe(_r, z3.Re(string))
        # to point if the string starts or ends with *
        flag = [0, 0]
        if string.startswith('*'):
            string = string[1:]
            flag[0] = 1
        if string.endswith('*'):
            string = string[0:-1]
            flag[1] = 1
        string = string.split("*")
        cache = []
        for line in string:
            cache.append(z3.Re(line))
            cache.append(self.__regular_mqtt_set)
        cache = cache[0:-1]
        if flag[0]:
            cache.insert(0, self.__regular_mqtt_set)
        if flag[1]:
            cache.append(self.__regular_mqtt_set)
        re_model = z3.Concat(cache)
        main_smt = z3.InRe(_r, re_model) 

        pattern = []
        for i in range(length-1):
            pattern.append(self.__regular_plus_set)
            pattern.append(Re('/'))

        pattern.append(self.__regular_plus_set)
        pattern = z3.Concat(pattern)
        main_smt = And(InRe(_r, pattern), main_smt) 
        s = Solver()
        s.add(main_smt)
        while s.check() == z3.sat:
            result = s.model()
            s.add(Not(_r == result))
            print(result)
        
    def naive_encode(self, policy):
        # encode but do not encode + and # in subscribe
        smts = policy["Statement"]
        
        smt_allow_cache = []
        smt_deny_cache = []

        assign = String("Action")
        for smt in smts:
            action = smt['Action']
            effect = smt['Effect']
            resource = smt['Resource']
            if type(resource) == str:
                resource = [resource]
            resource_cache = []
            for cell in resource:
                smt_cell = self.__naive_str_constrains(cell, action)
                resource_cache.append(smt_cell)
            result = And(assign == action, Or(resource_cache))
            if effect == "Allow":
                smt_allow_cache.append(result)
            if effect == "Deny":
                smt_deny_cache.append(result)

        result = And(Or(smt_allow_cache), Not(Or(smt_deny_cache)))
        return result

    def deep_encode(self, policy):
        # encode a policy deeply including + and #
        smts = policy["Statement"]
        smt_allow_cache = []
        smt_deny_cache = []

        assign = String("Action")

        for smt in smts:
            action = smt['Action']
            effect = smt['Effect']
            resource = smt['Resource']

            assign = String("Action")
            if type(resource) == str:
                resource = [resource]
            resource_cache = []
            for cell in resource:
                smt_cell = self.__deep_str_constrains(cell, action, effect)
                resource_cache.append(smt_cell)
            result = And(assign == action, Or(resource_cache))
            if effect == "Allow":
                smt_allow_cache.append(result)
            if effect == "Deny":
                smt_deny_cache.append(result)
        if smt_deny_cache:
            result = And(Or(smt_allow_cache), Not(Or(smt_deny_cache)))
        else:
            if not smt_allow_cache:
                return False
            result = Or(smt_allow_cache)
            # print(simplify(result))
        return result
    
    def deep_encode_to_naive(self, policy):
        pass
        
    def naive_encode_single(self, smt):
        action = smt['Action']
        effect = smt['Effect']
        resource = smt['Resource']

        assign = String('Action')

        if type(resource) == str:
            resource = [resource]
            resource_cache = []
            for cell in resource:
                smt_cell = self.__naive_str_constrains(cell, action)
                resource_cache.append(smt_cell)
            result = And(assign == action, Or(resource_cache))
            if effect == "Allow":
                return result
            if effect == "Deny":
                return Not(result)
    
    def deep_encode_single(self, smt):
        action = smt['Action']
        effect = smt['Effect']
        resource = smt['Resource']

        assign = String("Action")
        if type(resource) == str:
            resource = [resource]
            resource_cache = []
            for cell in resource:
                smt_cell = self.__deep_str_constrains(cell, action, effect)
                resource_cache.append(smt_cell)
            result = And(assign == action, Or(resource_cache))
            if effect == "Allow":
                return result
            if effect == "Deny":
                return Not(result)
