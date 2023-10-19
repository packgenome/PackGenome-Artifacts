#!/usr/bin/env python3
# -*- encoding: utf-8 -*-
'''
@File    :   callerToSimAnalysis.py
@Time    :   2022/05/19 15:43:05
@Author  :   Spook 
@Version :   1.0
@Contact :   
@License :   BSD
@Desc    :   None
'''
import sys, getopt
import os
import json
import plyara
from SimilarityAnalysis import *
from itertools import combinations
from LogGeneration import samples_extract, jsonfiles_extract
import optparse
from time import time

rule_Index = 0

#rule_json_info->yara_rule
def yara_rule_transform(yara_rule):
    result = f"rule {yara_rule['rule_name']}\n"
    result += "{\n"
    result += yara_rule['raw_meta']
    result += "\t" + yara_rule['raw_strings']
    result += yara_rule['raw_condition'] + "}\n\n"
    return result

#similarity analysis
def getYaraRule(json_pair, rulename):
    # PATCH 1
    fullmatched_list = []
    partialmatched_list = []
    sresult = json2type(json_pair[0])
    tresult = json2type(json_pair[1])
    cfull, cpartial = compareBytesList(sresult, tresult)

    if len(json_pair)==3:
        # compare three trace file mode
        t2result = json2type(json_pair[2])
        cleanup()
        c1full, c1partial = compareBytesList(sresult, t2result)
        cleanup()
        c2full, c2partial = compareBytesList(tresult, t2result)
        cleanup()
        fullmatched_list, partialmatched_list = tripleCompareFilter(cfull, cpartial, c1full, c1partial, c2full, c2partial)

    if len(partialmatched_list)==0:
        markDifferentBytes(cpartial)
    else:
        markDifferentBytes(partialmatched_list)

    if len(fullmatched_list)==0:
        return findKernelBytes(cfull, cpartial, rulename)
    else:
        return findKernelBytes(fullmatched_list, partialmatched_list, rulename)

def extract_strings(rule):
    if isinstance(rule, str):
        rule = eval(rule)
    string_list = []
    for i in range(len(rule["strings"])):
        string_list.append(rule["strings"][i]["value"][1:-1].strip())
    return set(string_list)

def distillRules(rlist, converge):
    yara_parser_tmp = plyara.Plyara()
    result_list = []
    empty_string = ""
    empty_times = 0
    for r in rlist:
        already = False
        try:
            if r!=None:
                tmp_r = yara_parser_tmp.parse_string(r)[0]
                string_set = extract_strings(tmp_r)
                for r_s in result_list:
                    keystr_set = extract_strings(r_s)
                    if converge:
                        if keystr_set.issubset(string_set):
                            already = True
                            break
                        elif string_set.issubset(keystr_set):
                            already = True
                            result_list.remove(r_s)
                            result_list.append(tmp_r)
                            break
                    else:
                        if string_set == keystr_set and tmp_r["condition_terms"] == r_s["condition_terms"]:
                            already = True
                            break
                if not already:
                    result_list.append(tmp_r)
        except:
            empty_string = r.split("\n")[0].lstrip("rule ")
            empty_times += 1
            continue
        finally:
            yara_parser_tmp.clear()
    return result_list, {empty_string: empty_times}

# TODO same-config-cross-version
def yara_meta_edit(yara_rule):
    metainfo = "\tmeta:\n"
    metainfo += '\t\tpacker="' + yara_rule['info_packer'] + '"\n'
    metainfo += '\t\tgenerator="PackGenome"\n'
    if 'meta_versions' in yara_rule.keys():
        versions = " ".join(yara_rule['meta_versions'])
        metainfo += '\t\tversions="' + versions + '"\n'
        yara_rule['raw_meta'] = metainfo
        return
    else:
        metainfo += '\t\tversion="' + yara_rule['info_version'] + '"\n'
    if 'meta_configs' in yara_rule.keys() and len(yara_rule['meta_configs']) > 1:
        configs = " ".join(yara_rule['meta_configs'])
        metainfo += '\t\tconfigs="' + configs + '"\n'
    else:
        metainfo += '\t\tconfig="' + yara_rule['info_config'] + '"\n'
    yara_rule['raw_meta'] = metainfo

def yara_rule_edit(yara_rule, info):
    # yara_rule['rule_name'] = info['rulename']
    metainfo = "\tmeta:\n"
    metainfo += '\t\tpacker="' + info['packername'] + '"\n'
    metainfo += '\t\tgenerator="PackGenome"\n'
    metainfo += '\t\tversion="' + info['version'] + '"\n'
    metainfo += '\t\tconfig="' + info['config'] + '"\n'
    yara_rule['raw_meta'] = metainfo
    # plus info
    yara_rule['info_packer'] = info['packername']
    yara_rule['info_version'] = info['version']
    yara_rule['info_config'] = info['config']

def rulesCheck(rule):
    yara_parser_tmp = plyara.Plyara()
    empty_string = ""
    try:
        tmp = yara_parser_tmp.parse_string(rule)[0]
        return tmp # 一致
    except:
        empty_string = rule.split("\n")[0].lstrip("rule ")
        return empty_string # strings 空    

def combination_rule_edit(rules_list, packername):
    index = 0
    for yara_rule in rules_list: # 暂不需要统计内部情况
        yara_rule['rule_name'] = "_".join(["packer", packername, str(index)])
        metainfo = "meta:\n"
        metainfo += '\t\tpacker="' + packername + '"\n'
        metainfo += '\t\tgenerator="PackGenome"\n'
        metainfo += '\t\tindex="' + str(index) + '"\n'
        yara_rule['raw_meta'] = metainfo
        index += 1

def FullCombination(packer, converge):
    if not packer["jsonfiles"]:
        print("    empty!")
        return
    json_pairs = combinations(packer["jsonfiles"], 2) 
    rules = []
    for pair in json_pairs:
        tmp_name = "tmp_" + packer["name"]
        rule = getYaraRule(pair, tmp_name)
        rules.append(rule)
    
    rules_list, empty_list = distillRules(rules, converge)
    if "" not in empty_list.keys():
        for tmp, times in empty_list.items():
            pass
            #print("[empty strings] " + tmp + ": " + str(times))
    combination_rule_edit(rules_list, packer["name"])
    return rules_list
    
# accessible
def CheckCombination(packer, converge):
    Final_rules = {}
    for version in packer["versions"]:
        Final_rules[version] = {}
        for config in packer["versions"][version]:
            info = {"packername":packer["name"], "version":version, "config":config}
            info["rulename"] = "_".join(["packer", packer["name"], version, config])
            if len(packer["versions"][version][config]) <= 1:
                Final_rules[version][config] = ["pass"]
                continue

            # PATCH 2
            if len(packer["versions"][version][config])==3:
                tmp_name = info["rulename"]
                rule = getYaraRule((packer["versions"][version][config]), tmp_name)
                # try:
                #     rule = getYaraRule((packer["versions"][version][config]), tmp_name)
                # except Exception as e:
                #     print(e)
                #     print("[-] Failed: " + str(packer["versions"][version][config]))
            else:
                for pair in combinations(packer["versions"][version][config], 2):
                    tmp_name = info["rulename"]
                    rule = getYaraRule(pair, tmp_name)
                    # try:
                    #     rule = getYaraRule(pair, tmp_name)
                    # except Exception as e:
                    #     print(e)
                    #     print("[-] Failed: " + pair[0] + " " + pair[1])

            checkResult = rulesCheck(rule)
            if isinstance(checkResult, str):
                print("[empty strings] " + checkResult)
                Final_rules[version][config] = ["empty"]
            else:
                yara_rule_edit(checkResult, info)
                Final_rules[version][config] = ["succ", checkResult]

        # compare amoung configs

        tmp_rules = []
        for config, rule_condition in Final_rules[version].items():
            if rule_condition[0] == "succ":
                tmp_rules.append(rule_condition[1])
        
        result_rules = distillRules_new(tmp_rules, converge)
        # unanimous
        if len(result_rules) == 1:
            Final_rules[version]["comb_result"] = "success"
            for k, v in result_rules.items():
                tmp = eval(k)
                tmp['meta_configs'] = [tmp['info_config']]
                for rem in v:
                    tmp['meta_configs'].append(rem['info_config'])

            yara_meta_edit(tmp)
            tmp['rule_name'] = "_".join(["packer", tmp["info_packer"], tmp["info_version"]])
            Final_rules[version]["combination"] = tmp

        else:
            Final_rules[version]["comb_result"] = "failed"
            Final_rules[version]["combination"] = []
            for k, v in result_rules.items():
                tmp = eval(k)
                tmp['meta_configs'] = [tmp['info_config']]
                for rem in v:
                    tmp['meta_configs'].append(rem['info_config'])
                yara_meta_edit(tmp)
                Final_rules[version]["combination"].append(tmp)
    
    tmp_rules = []
    for vrs, cont in Final_rules.items():
        if cont["comb_result"] == "success":
            tmp_rules.append(cont["combination"])
        else:

            Final_rules["full_comb_result"] = "failed"
            Final_rules["full_combination"] = []
            return Final_rules
    
    result_rules = distillRules_new(tmp_rules, converge)
    # unanimous
    if len(result_rules) == 1:
        Final_rules["full_comb_result"] = "success"

        for k, v in result_rules.items():
            tmp = eval(k)
            tmp['meta_versions'] = [tmp['info_version']]
            for rem in v:
                tmp['meta_versions'].append(rem['info_version'])
        yara_meta_edit(tmp)
        tmp['rule_name'] = "_".join(["packer", tmp["info_packer"]])
        Final_rules["full_combination"] = tmp

    else:
        Final_rules["full_comb_result"] = "failed"
        Final_rules["full_combination"] = []
        for k, v in result_rules.items():
            tmp = eval(k)
            tmp['meta_versions'] = [tmp['info_version']]
            for rem in v:
                tmp['meta_versions'].append(rem['info_version'])
            yara_meta_edit(tmp)
            Final_rules["full_combination"].append(tmp)

    return Final_rules

def distillRules_new(rlist, converge):
    result_list = {}
    for r in rlist:
        already = False
        string_set = extract_strings(r)
        for r_s in result_list.keys():
            keystr_set = extract_strings(r_s)
            if converge:
                if keystr_set.issubset(string_set):
                    already = True
                    result_list[r_s].append(r)
                    break
                elif string_set.issubset(keystr_set):
                    already = True
                    result_list[str(r)] = result_list[r_s].copy()
                    result_list[str(r)].append(eval(r_s))
                    del result_list[r_s] 
                    break
            else:
                if string_set == keystr_set and r["condition_terms"] == eval(r_s)["condition_terms"]:
                    already = True
                    result_list[r_s].append(r)
                    break
        if not already:
            result_list[str(r)] = []
    return result_list

def FinalResultAnalyze(packername, Final_rules):
    print("all version combination: " + Final_rules["full_comb_result"])
    for version, content in Final_rules.items():
        succ = []
        empty = []
        pass_ = []
        result = ""
        if version == "full_comb_result" or version == "full_combination":
            continue
        for config, rules in content.items():
            if config == "combination":
                continue
            if config == "comb_result":
                result = rules
                continue
            if rules[0] == "succ":
                succ.append(config)
            elif rules[0] == "empty":
                empty.append(config)
            elif rules[0] == "pass":
                pass_.append(config)
        print(f"{version} result:{result} succ:{str(len(succ))} empty:{str(len(empty))} pass:{str(len(pass_))}")
        if succ:
            print("succ:"," ".join(succ))
        if empty:
            print("empty:"," ".join(empty))
        if pass_:
            print("pass:"," ".join(pass_))

def YaraOutput2File_old(testpackers, inaccessibleTest, yarafile, jsondir):
    with open(yarafile, "w") as f:
        f.write('import "pe"\n')
        f.write('import "dotnet"\n\n')
        rules_json = os.listdir(jsondir)
        if not inaccessibleTest:
            for jsonfile in rules_json:
                packername = jsonfile.split("_")[0]
                if testpackers and packername.lower() not in testpackers:
                    continue
                f.write(f'// {packername}\n')
                with open(os.path.join(jsondir, jsonfile)) as js:
                    tmpjson = json.load(js)
                    if tmpjson["full_comb_result"] == "success":
                        f.write(yara_rule_transform(tmpjson["full_combination"]) + "\n")
                    elif tmpjson["full_combination"]:
                        for filtered_verrule in tmpjson["full_combination"]:
                            f.write(yara_rule_transform(filtered_verrule) + "\n")
                    else:
                        for version, content in tmpjson.items():
                            if version == "full_comb_result" or version == "full_combination":
                                continue
                            if content["comb_result"] == "success":
                                f.write(yara_rule_transform(content["combination"]) + "\n")
                            elif content["comb_result"] == "failed":
                                if content["combination"]:
                                    for filtered_rule in content["combination"]:
                                        f.write(yara_rule_transform(filtered_rule) + "\n")
        # inaccessible
        else:
            for jsonfile in rules_json:
                packername = jsonfile.split("_")[0]
                if testpackers and packername.lower() not in testpackers:
                    continue
                f.write(f'// {packername}\n')
                with open(os.path.join(jsondir, jsonfile)) as js:
                    tmpjson = json.load(js)
                    for rule in tmpjson:
                        f.write(yara_rule_transform(rule) + "\n")

def YaraOutput2File(testpackers, inaccessibleTest, output_dir, yaraname, jsondir):
    rules_json = os.listdir(jsondir)
    file_list = []
    if not inaccessibleTest:
        for jsonfile in rules_json:
            packername = jsonfile.split("_")[0]
            if testpackers and packername.lower() not in testpackers:
                continue
            outputfile = os.path.join(output_dir, packername + yaraname + ".yar")
            file_list.append(outputfile)
            with open(outputfile, "w") as yf:
                yf.write('import "pe"\n')
                yf.write('import "dotnet"\n\n')
                with open(os.path.join(jsondir, jsonfile)) as js:
                    tmpjson = json.load(js)
                    if tmpjson["full_comb_result"] == "success":
                        yf.write(yara_rule_transform(tmpjson["full_combination"]) + "\n")
                    elif tmpjson["full_combination"]:
                        for filtered_verrule in tmpjson["full_combination"]:
                            yf.write(yara_rule_transform(filtered_verrule) + "\n")
                    else:
                        for version, content in tmpjson.items():
                            if version == "full_comb_result" or version == "full_combination":
                                continue
                            if content["comb_result"] == "success":
                                yf.write(yara_rule_transform(content["combination"]) + "\n")
                            elif content["comb_result"] == "failed":
                                if content["combination"]:
                                    for filtered_rule in content["combination"]:
                                        yf.write(yara_rule_transform(filtered_rule) + "\n")
    # inaccessible
    else:
        for jsonfile in rules_json:
            packername = jsonfile.split("_")[0]
            if testpackers and packername.lower() not in testpackers:
                continue
            outputfile = os.path.join(output_dir, packername + yaraname + ".yar")
            file_list.append(outputfile)
            with open(outputfile, "w") as yf:
                with open(os.path.join(jsondir, jsonfile)) as js:
                    tmpjson = json.load(js)
                    for rule in tmpjson:
                        yf.write(yara_rule_transform(rule) + "\n")
    return file_list

def Duplication_Info(yarafiles, output_file, converge):
    with open(output_file, "w") as of:
        for yarafile in yarafiles:
            of.write(os.path.basename(yarafile) + "\n")
            yara_parser_tmp = plyara.Plyara()
            with open(yarafile) as f:
                tmp_r = yara_parser_tmp.parse_string(f.read())
                of.write("length before: " + str(len(tmp_r)) + "\n")
                sss = distillRules_new(tmp_r, converge)
                of.write("length after: " + str(len(sss)) + "\n")
                for k, v in sss.items():
                    of.write("-"*15 + "\n")
                    of.write(eval(k)['rule_name'] + "\n")
                    for vs in v:
                        of.write(vs['rule_name'] + "\n")
            of.write("\n\n")

def rule_generate():
    with open(os.path.join("./config/GenConfig.json"), "r") as f:
        configs = json.load(f)
    if configs["inaccessibleTest"]:
        test_packers = list(configs["inaccessible_packers"])    
    else:
        test_packers = configs["accessible_packers"]      
    if configs["inaccessibleTest"]:
        root_dir = configs['inaccessible_dir']
        output_dir = configs['inaccessible_output']
        print(222)
        result_json = samples_extract(list(configs["inaccessible_packers"]) , configs["inaccessible_dir"], True, configs["inaccessible_contents"])
        json_loc = jsonfiles_extract(result_json, root_dir, True, configs['inaccrecordName'])
        with open(configs['inaccrecordName'] + ".json") as f:
            json_loc = json.load(f)
    else:
        root_dir = configs['accessible_dir']
        output_dir = configs['accessible_output']
        result_json = samples_extract(configs["accessible_packers"],configs["accessible_dir"], False, configs["accessible_contents"])
        json_loc = jsonfiles_extract(result_json, root_dir, False, configs['accrecordName'])
        with open(configs['accrecordName'] + ".json") as f:
            json_loc = json.load(f)
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    
    if configs['generation']:
        for packer in json_loc:
            # [1] generate rules to the list 'rules'
            packername = packer["name"]
            print("[+] packer: " + packername)
            if configs['inaccessibleTest']:
                rules_dict = FullCombination(packer, configs['converge'])
                with open(os.path.join(output_dir, packername + "_result_dict.json"), "w") as f:
                    f.write(json.dumps(rules_dict, indent=2))
            else:
                rules_dict = CheckCombination(packer, configs['converge'])
                with open(os.path.join(output_dir, packername + "_result_dict.json"), "w") as f:
                    f.write(json.dumps(rules_dict, indent=2))
                FinalResultAnalyze(packername, rules_dict)
    if configs['output']:
        if not os.path.exists(configs['rules_dir']):
            os.makedirs(configs['rules_dir'])

        if configs['duplication_info']:
            if not configs['inaccessibleTest']:
                yarafiles = YaraOutput2File(test_packers, configs['inaccessibleTest'], configs['rules_dir'], configs['accessible_suffix'], configs['accessible_output'])
            elif configs['inaccessibleTest']:
                yarafiles = YaraOutput2File(test_packers, configs['inaccessibleTest'], configs['rules_dir'], configs['inaccessible_suffix'], configs['inaccessible_output'])
            Duplication_Info(yarafiles, configs['duplication_file'], configs['converge'])
        else:
            if not configs['inaccessibleTest'] and configs['accessible_yara']:
                YaraOutput2File_old(test_packers, configs['inaccessibleTest'], os.path.join(configs['rules_dir'], configs['accessible_yara'] ), configs['accessible_output'])
            elif configs['inaccessibleTest'] and configs['inaccessible_yara']:
                YaraOutput2File_old(test_packers, configs['inaccessibleTest'], os.path.join(configs['rules_dir'], configs['inaccessible_yara']), configs['inaccessible_output'])
                                                                                            
def main(argv):
    config_dir = "config"

    with open(os.path.join(config_dir, "GenConfig.json"), "r") as f:
        configs = json.load(f)

    if configs['inaccessibleTest']:
        root_dir = configs['inaccessible_dir']
        output_dir = configs['inaccessible_output']
        if configs['updateJson']:
            result_json = samples_extract(root_dir, True, configs['injsonName'])
            json_loc = jsonfiles_extract(result_json, root_dir, True, configs['inrecordName'])
        else:    
            with open(configs['inrecordName'] + ".json") as f:
                json_loc = json.load(f)

    else:
        root_dir = configs['accessible_dir']
        output_dir = configs['accessible_output']
        if configs['updateJson']:
            result_json = samples_extract(root_dir, False, configs['accjsonName'])
            json_loc = jsonfiles_extract(result_json, root_dir, False, configs['accrecordName'])
        else:    
            with open(configs['accrecordName'] + ".json") as f:
                json_loc = json.load(f)

    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    testpackers = configs['testpackers'] # testpackers = ["fsg"] 
    for i in range(len(testpackers)):
        testpackers[i] = testpackers[i].lower()

    if configs['generation']:
        for packer in json_loc:
            # [1] generate rules to the list 'rules'
            packername = packer["name"]
            
            if packername.lower() in testpackers or not testpackers:
                print("[+] packer: " + packername)
                if configs['inaccessibleTest']:
                    rules_dict = FullCombination(packer, configs['converge'])
                    with open(os.path.join(output_dir, packername + "_result_dict.json"), "w") as f:
                        f.write(json.dumps(rules_dict, indent=2))
                else:
                    rules_dict = CheckCombination(packer, configs['converge'])
                    with open(os.path.join(output_dir, packername + "_result_dict.json"), "w") as f:
                        f.write(json.dumps(rules_dict, indent=2))
                    FinalResultAnalyze(packername, rules_dict)
                    
    if configs['output']:
        if not os.path.exists(configs['rules_dir']):
            os.makedirs(configs['rules_dir'])

        if configs['duplication_info']:
            if not configs['inaccessibleTest']:
                yarafiles = YaraOutput2File(testpackers, configs['inaccessibleTest'], configs['rules_dir'], configs['accessible_suffix'], configs['accessible_output'])
            elif configs['inaccessibleTest']:
                yarafiles = YaraOutput2File(testpackers, configs['inaccessibleTest'], configs['rules_dir'], configs['inaccessible_suffix'], configs['inaccessible_output'])
    
            Duplication_Info(yarafiles, configs['duplication_file'], configs['converge'])
        
        else:
            if not configs['inaccessibleTest'] and configs['accessible_yara']:
                YaraOutput2File_old(testpackers, configs['accessibleTest'], os.path.join(configs['rules_dir'], configs['accessible_yara'] + ".yar"), configs['accessible_output'])
            elif configs['inaccessibleTest'] and configs['inaccessible_yara']:
                YaraOutput2File_old(testpackers, configs['inaccessibleTest'], os.path.join(configs['rules_dir'], configs['inaccessible_yara'] + ".yar"), configs['inaccessible_output'])

if __name__ == "__main__":
    starttime=time()
    oParser = optparse.OptionParser(usage='usage: %prog \n')
    oParser.add_option('-i', '--inaccessible', action="store_true") 
    (options, args) = oParser.parse_args()
    with open("./config/GenConfig.json", "r") as f:
        configs = json.load(f)
    configs["inaccessibleTest"]=options.inaccessible
    with open("./config/GenConfig.json", "w") as f:
        f.write(json.dumps(configs,indent=2))
    rule_generate()
    print("total:"+str(time()-starttime))
