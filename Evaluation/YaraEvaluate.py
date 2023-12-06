from email.policy import default
import optparse
import os
from datetime import datetime
import json
import random
import shutil
from time import time

class YaraMatch(object):
    def __init__(self, packer:str, configs):
        self.packer = packer
        self.packgenome_rule = configs["packgenome_rule"]
        self.artificial_rule = configs["artificial_rule"]
        self.autoyara_rule = configs["autoyara_rule"]
        self.yabin_rule=configs["yabin_rule"]
        self.yaragenerator_rule=configs["yaragenerator_rule"]
        self.yargen_rule=configs["yargen_rule"]
        self.thread = configs["thread"]
        self.test_mode=configs["test_mode"]
        self.other_tools_test=configs["other_tools_test"]  
        self.inaccessible_test=configs["inaccessible_test"]
        # tagon -- LPD:labeled packed program dataset
        if configs["test_mode"]=="tagon":
            if self.inaccessible_test:
                self.testset_path = os.path.join(configs["LPD1_testset"], packer)+"/"
            else:
                self.testset_path = os.path.join(configs["LPD_testset"], packer)+"/"
            self.output_file = packer + configs["yara_output_suffix"]+"_matched.json"
            if configs["other_tools_test"]:
                self.output_dir = configs["output_dir"]+"/tagon_optional/"
                self.autoyara_rule = self.autoyara_rule.replace(".yar",'_accessible.yar')
                self.efficiency_result = {os.path.basename(self.autoyara_rule):0, os.path.basename(self.yabin_rule):0, os.path.basename(self.yaragenerator_rule):0, os.path.basename(self.yargen_rule):0}
            else:
                if self.inaccessible_test:
                    self.output_dir = configs["output_dir"]+"/tagon_inaccessible/"
                    self.packgenome_rule = self.packgenome_rule.replace(".yar",'_inaccessible.yar')
                    self.autoyara_rule = self.autoyara_rule.replace(".yar",'_inaccessible.yar')
                else:
                    self.output_dir = configs["output_dir"]+"/tagon_accessible/"
                    self.packgenome_rule = self.packgenome_rule.replace(".yar",'_accessible.yar')
                    self.autoyara_rule = self.autoyara_rule.replace(".yar",'_accessible.yar')
                self.efficiency_result = {os.path.basename(self.packgenome_rule):0, os.path.basename(self.artificial_rule):0, os.path.basename(self.autoyara_rule):0}
        else:
        # NPD -- non-packed program dataset
            self.testset_path = configs["NPD_testset"]
            self.output_dir = configs["output_dir"]+"/non_pack/"
            self.output_file = "yara_matched.json"
            self.packgenome_rule = self.packgenome_rule.replace(".yar",'_accessible.yar')
            self.autoyara_rule = self.autoyara_rule.replace(".yar",'_accessible.yar')
            self.efficiency_result = {os.path.basename(self.packgenome_rule):0, os.path.basename(self.artificial_rule):0, os.path.basename(self.autoyara_rule):0}
        self.tmp_path = "tmp_path/"
        samples = [os.path.join(self.testset_path, file) for file in os.listdir(self.testset_path)]
        self.match_result=dict((k, {}) for k in samples)
        if not os.path.exists(self.tmp_path):
            os.mkdir(self.tmp_path)     
        if not os.path.exists(self.output_dir):
            os.mkdir(self.output_dir)         
    
    def yara_match_all(self):
        if not self.other_tools_test:
            self.yara_match(self.packgenome_rule)
            self.yara_match(self.artificial_rule)
            self.yara_match(self.autoyara_rule)
        else:
            self.yara_match(self.yabin_rule)
            self.yara_match(self.yaragenerator_rule)
            self.yara_match(self.autoyara_rule)
            self.yara_match(self.yargen_rule)
        with open(os.path.join(self.output_dir, self.output_file), "w") as f:
            f.write(json.dumps(self.match_result, sort_keys=True, indent=2))
    
    def yara_match(self, rule_file):
        rule_name=os.path.basename(rule_file)
        txtfile = os.path.join(self.tmp_path, rule_name.split(".")[0] + "_match.txt")
        print(f"yara -p {self.thread} -w -C {rule_file} -r {self.testset_path}")
        starttime = time()
        os.system(f"yara -p {self.thread} -w -C {rule_file} -r {self.testset_path} >> {txtfile}")
        self.efficiency_result[rule_name] += time() - starttime
        with open(txtfile) as f:
            line = f.readline()
            while line:
                rule, sample = line.strip().split(" ")
                sample = sample.replace("\\", "/").replace("//", "/")
                if rule_name not in self.match_result[sample].keys():
                    self.match_result[sample][rule_name] = [rule]
                else:
                    self.match_result[sample][rule_name].append(rule)
                line = f.readline()
        os.remove(txtfile)

class YaraAnalysis(object):
    def __init__(self, json_result:str, packer:str, configs, efficiency):
        self.json_result = json_result
        self.packer = packer
        self.configs=configs
        self.efficiency=efficiency
        self.test_mode=configs["test_mode"]
        self.inaccessible_test=configs["inaccessible_test"]
        if configs["test_mode"]=="tagon":
            if configs["other_tools_test"]:
                self.output_dir = configs["output_dir"]+"/tagon_optional/"
                self.yara_rules=[os.path.basename(configs["autoyara_rule"].replace(".yar","_accessible.yar")), os.path.basename(configs["yabin_rule"]), os.path.basename(configs["yaragenerator_rule"]), os.path.basename(configs["yargen_rule"])]
            else:
                if self.inaccessible_test:
                    self.output_dir = configs["output_dir"]+"/tagon_inaccessible/"
                    self.yara_rules=[os.path.basename(configs["packgenome_rule"]).replace(".yar","_inaccessible.yar"), os.path.basename(configs["artificial_rule"]), os.path.basename(configs["autoyara_rule"]).replace(".yar","_inaccessible.yar")]
                else:
                    self.output_dir = configs["output_dir"]+"/tagon_accessible/"
                    self.yara_rules=[os.path.basename(configs["packgenome_rule"]).replace(".yar","_accessible.yar"), os.path.basename(configs["artificial_rule"]), os.path.basename(configs["autoyara_rule"]).replace(".yar","_accessible.yar")]
        else:
            self.output_dir = configs["output_dir"]+"/non_pack/"
            self.yara_rules=[os.path.basename(configs["packgenome_rule"]).replace(".yar","_accessible.yar"), os.path.basename(configs["artificial_rule"]), os.path.basename(configs["autoyara_rule"]).replace(".yar","_accessible.yar")]   
        self.FP_samples = dict((k, []) for k in self.yara_rules)
        self.TP_samples = dict((k, []) for k in self.yara_rules)
        self.FN_samples = dict((k, []) for k in self.yara_rules)
        self.TN_samples = dict((k, []) for k in self.yara_rules)
        self.TD_samples = dict((k, []) for k in self.yara_rules)
        self.FPR = dict((k, []) for k in self.yara_rules)
        self.TPR = dict((k, []) for k in self.yara_rules)
        self.FNR = dict((k, []) for k in self.yara_rules)
        self.TNR = dict((k, []) for k in self.yara_rules)
        self.TDR = dict((k, []) for k in self.yara_rules)
        self.ACC = dict((k, []) for k in self.yara_rules)
        with open(self.json_result, "r") as f:
            self.match_result = json.load(f)

    def analysis(self):
        for sample, content in self.match_result.items():
            for yarafile in self.yara_rules:
                if yarafile in content.keys():
                    if sample not in self.TD_samples[yarafile]:
                        self.TD_samples[yarafile].append(sample)
                    non_target = False
                    target = False
                    for rule in content[yarafile]:
                        if self.packer in rule.lower():
                            target = True
                        # fsg and mew are sharing similar unpacking routines
                        elif self.packer=="fsg" and "mew" in rule.lower():
                            target=True
                        elif self.packer=="mew" and "fsg" in rule.lower():
                            target=True
                        # winlicense and themida are sharing similar unpacking routines
                        elif self.packer=="winlicense" and "themida" in rule.lower():
                            target=True
                        elif self.packer=="themida" and "winlicense" in rule.lower():
                            target=True    
                        else:
                            non_target = True
                    if target:
                        self.TP_samples[yarafile].append(sample)
                    else:
                        self.FN_samples[yarafile].append(sample)
                    if non_target:
                        self.FP_samples[yarafile].append(sample)
                    else:
                        self.TN_samples[yarafile].append(sample)
                else:
                    self.FN_samples[yarafile].append(sample)
                    self.TN_samples[yarafile].append(sample)

    def calcRatios(self):
        if self.test_mode =="tagon":
            for yarafile in self.yara_rules:
                FP = len(self.FP_samples[yarafile])
                FN = len(self.FN_samples[yarafile])
                TP = len(self.TP_samples[yarafile])
                TN = len(self.TN_samples[yarafile])
                TD = len(self.TD_samples[yarafile])
                self.FPR[yarafile] = FP*100 / (FP + TN)
                self.FNR[yarafile] = FN*100 / (FN + TP)
                self.TPR[yarafile] = TP*100 / (TP + FN)
                self.TNR[yarafile] = TN*100 / (TN + FP)
                self.TDR[yarafile]= TD*100/len(self.match_result)
                self.ACC[yarafile]= (TP+TN)/(TP+TN+FP+FN)
        else:
            for yarafile in self.yara_rules:
                self.FPR[yarafile] = len(self.FP_samples[yarafile]) / len(self.match_result) 
                self.TDR[yarafile]= len(self.FP_samples[yarafile]) / len(self.match_result) 

    def analysis_output(self):
        if self.test_mode=="tagon":
            if not self.inaccessible_test:
                result_path="./result/acc_lpd.txt"
            else:
                result_path="./result/inacc_lpd1.txt"
            with open(result_path, "a") as f:
                f.write("-"*30 + "\n")
                f.write(str(datetime.now())+"\n")
                f.write("[+]" + self.packer + "\n")
                for yaraName, time in self.efficiency.items():
                    f.write(yaraName+"\n")
                    # f.write("\tFPR:"+str(round(self.FPR[yaraName],3))+"\n")
                    # f.write("\tFNR:"+str(round(self.FNR[yaraName],3))+"\n")
                    # f.write("\tTDR:"+str(round(self.TDR[yaraName],3))+"\n")
                    # f.write("\tACC:"+str(round(self.ACC[yaraName],3))+"\n")
                    # f.write("\ttime:"+ str(round(time,2)) + "\n")
                    f.write("\tFPR:"+'%.3g'%self.FPR[yaraName]+"\n")
                    f.write("\tFNR:"+'%.3g'%self.FNR[yaraName]+"\n")
                    f.write("\tTDR:"+'%.3g'%self.TDR[yaraName]+"\n")
                    f.write("\ttime:"+ str(round(time,2)) + "\n")

def YaraMatchProcedure(IYaraMatch:YaraMatch):
    IYaraMatch.yara_match_all()
    shutil.rmtree(IYaraMatch.tmp_path)
    return os.path.join(IYaraMatch.output_dir, IYaraMatch.output_file)

def YaraAnalysisProcedure(IYaraAnalysis:YaraAnalysis):  
    analysis_output_dir=IYaraAnalysis.output_dir+"analysis/"
    if not os.path.exists(analysis_output_dir):
        os.makedirs(analysis_output_dir)
    IYaraAnalysis.analysis()
    IYaraAnalysis.calcRatios()
    analysis_output_path= analysis_output_dir+IYaraAnalysis.packer + IYaraAnalysis.configs["yara_output_suffix"]+".json"
    tmp_dict = {}
    if IYaraAnalysis.test_mode=="tagon":
        for yara_rule in IYaraAnalysis.yara_rules:
            print("[+] " + yara_rule)
            print("    FPR: "+'%.3g'%IYaraAnalysis.FPR[yara_rule])
            print("    FNR: "+'%.3g'%IYaraAnalysis.FNR[yara_rule])
            print("    TDR: "+'%.3g'%IYaraAnalysis.TDR[yara_rule])
            tmp_dict[yara_rule] = {"FP_number":len(IYaraAnalysis.FP_samples[yara_rule]), "FP_samples":IYaraAnalysis.FP_samples[yara_rule], "FN_number":len(IYaraAnalysis.FN_samples[yara_rule]), "FN_samples":IYaraAnalysis.FN_samples[yara_rule]}
    else:
        for yara_rule in IYaraAnalysis.yara_rules:
            tmp_dict[yara_rule] = {"FP_number":len(IYaraAnalysis.FP_samples[yara_rule]), "FP_samples":IYaraAnalysis.FP_samples[yara_rule], "time": round(IYaraAnalysis.efficiency[yara_rule],2)}
    with open(os.path.join(analysis_output_path), "w") as f:
        f.write(json.dumps(tmp_dict, indent=2))
    IYaraAnalysis.analysis_output()
    os.removedirs
    return analysis_output_path

def YaraEvaluate(packer:str):
    with open("configs/EvaluationConfig.json", "r") as f:
        configs=json.load(f)
    MyMatch = YaraMatch(packer=packer,configs=configs)
    json_matched_result=YaraMatchProcedure(MyMatch)
    MyAnalysis = YaraAnalysis(json_result= json_matched_result, packer = packer, configs=configs, efficiency=MyMatch.efficiency_result)
    analysis_output_path=YaraAnalysisProcedure(MyAnalysis)
    return analysis_output_path

if __name__ == '__main__':
    YaraEvaluate("fsg")
