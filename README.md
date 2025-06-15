This tool entitled P-Verifier is designed for formal modeling and verification of AWS IoT Core Policies and report insecure policies (also see the paper published at ACM CCS 2022 http://www.xing-luyi.com/uploads/2/5/6/4/25640947/ccs_2022_iot_policy_long_version.pdf). 

P-Verifier includes three main check capabilities (Check 1 - Check 3) (see below). To make it even easier to use, in this release we provide an additional check capability, Check 4, which automatically infers security properties from the IoT Core policy.
 
# 0x01 Check Capabilities

## 1. Three Check Capabilities

1. Check 1: check whether an IoT Core Policy soundly excludes a permission as expected.
2. Check 2: check whether an IoT Core Policy is less-or-equally permissive than a reference policy.
3. Check 3: check whether multiple independent policies (intended to be assigned to independent users) share permissions.

## 2. A new, easier-to-use Check Capability 

4. Check 4:  automatically infer the property of the IoT Core policy (i.e., infer the resource/permission expected to exclude/deny in the policy and apply Check 1).

## 5. Check 5: Publish-Subscribe Overlap (SMT-based)

This check uses formal modeling (via `deep_encode_with_uuid`) to verify whether a policy grants both `iot:Publish` and `iot:Subscribe` permissions on the same topic. This could allow a user to send and receive messages on the same channel, potentially violating separation of privilege.

# 0x02 How to use

## Dependency

P-Verifier is developed using Python and relies on Z3 as the underlying SMT solver.

To use this tool, you need to install Z3, simply running `pip3 install -r requirements.txt` or `pip3 install z3-solver`. At time of writing this document, we use z3-solver version 4.11.2.0. Or you can see [Z3 Prover](https://github.com/Z3Prover/z3) for details.

At the time of this release, we use Python 3.10.8.

## Usage

The entrance of P-Verifier is main.py. You can run the program through the terminal and the results will be printed on the screen by default (or to a file, see below). 

We provide an “Examples” folder with this release, which includes files named such as “checkCapability1-Example1.json”. You can run P-Verifier against each of the files as the input. Each file includes an IoT Core policy to check, security properties and the related check capability to use (Check 1, 2 or 3, 4). 

If you want to use policies that not included in the example folder, please use the trans.py to convert your policy to standard format. The command is as below : 
python trans.py [your policy name]  [the check type you want to use]
For example, python trans.py CHALLENGE1-Error-71.json 5



We show examples of usage below. 

```bash
python3 main.py -i Examples/check1-2.json
```

Note that the “-i” argument specifies the input file. The result (insecure policy statements that violate specific properties) will be shown in the terminal. Alternatively,  You can use the “-o argument” to output the result to a file.

```bash
python3 main.py -i Examples/check1-2.json -o result.json
```

## 2. Result Types

0. No Error
1. Permission(s) is/are not excluded completely
2. Overly Permissive


## 3. A special note for Check 4

Check 4 is based on Check 1 to report if an IoT Core policy does not actually exclude a resource/permission as expected. To make Check 1 easier to use, we developed Check 4, which automatically finds out the resource/permission expected to be excluded by analyzing “deny” statements in the policy, and then apply Check 1. See an example in checkCapability4-Example1.json. To run it, simply use 

```bash
python3 main.py -i checkCapability4-Example1.json
```


