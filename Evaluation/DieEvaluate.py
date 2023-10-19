import optparse
import subprocess
import os
import shutil
import json
from datetime import datetime
from time import time


def sgname_normalize(sg_name):
    return sg_name.translate(str.maketrans('', '', ' -_')).lower()

class DieMatch(object):
    def __init__(self, packer:str, configs):
        self.packer=packer
        self.configs=configs
        self.die_path="diec"
        self.test_mode=configs["test_mode"]
        self.other_tools_test=configs["other_tools_test"] 
        self.inaccessible_test=configs["inaccessible_test"]
        if self.test_mode=="tagon":
            if self.inaccessible_test:
                self.testset_path = os.path.join(configs["LPD1_testset"], packer)+"/"
            else:
                self.testset_path = os.path.join(configs["LPD_testset"], packer)+"/"
            self.output_file = packer + configs["die_output_suffix"]+"_matched.json"
            if self.other_tools_test:
                self.output_dir=configs["output_dir"]+"/tagon_optional/"
            else:
                if self.inaccessible_test:
                    self.output_dir=configs["output_dir"]+"/tagon_inaccessible/"
                else:
                    self.output_dir=configs["output_dir"]+"/tagon_accessible/"
        else:
            self.output_file = "die_matched.json"
            self.output_dir=configs["output_dir"]+"/non_pack/"
            self.testset_path = configs["NPD_testset"]
        samples = [os.path.join(self.testset_path, file) for file in os.listdir(self.testset_path)]
        self.match_result=dict((k, {}) for k in samples)
        self.efficiency_result=0
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)

    def die_match(self):
        for sample in os.listdir(self.testset_path):
            sample_path = os.path.join(self.testset_path, sample)
            starttime=time()
            try:
                result = subprocess.check_output([self.die_path, "-j", sample_path])
                self.match_result[sample_path] = json.loads(result)['detects'][0]['values']
            except:
                with open("problem.txt", "a+") as f:
                    f.write(sample_path + "\n")
                self.match_result[sample_path] = []
            self.efficiency_result += (time()-starttime)
        with open(os.path.join(self.output_dir, self.output_file), "w") as f:
            f.write(json.dumps(self.match_result, sort_keys=True, indent=2))

class DieAnalysis(object):
    def __init__(self, json_result:str, packer:str, configs, efficiency):
        self.json_result = json_result
        self.packer = packer.lower()
        self.configs=configs
        self.efficiency=efficiency
        self.test_mode=configs["test_mode"]
        self.configs=configs
        self.FP_samples = []
        self.TP_samples = []
        self.FN_samples = []
        self.TN_samples = []
        self.TD_samples = []
        self.FPR = 0
        self.FNR = 0
        self.TPR = 0
        self.TNR = 0
        self.TDR = 0
        if self.test_mode=="tagon":
            if configs["other_tools_test"]:
                self.output_dir = configs["output_dir"]+"/tagon_optional/"
            else:
                if configs["inaccessible_test"]:
                    self.output_dir = configs["output_dir"]+"/tagon_inaccessible/"
                else:
                    self.output_dir = configs["output_dir"]+"/tagon_accessible/"
        else:
            self.output_dir = configs["output_dir"]+"/non_pack/"
        with open(self.json_result, "r") as f:
            self.match_result = json.load(f)

    def analysis(self):
        for sample, content in self.match_result.items():
            if content:
                non_target = False
                target = False
                for detect in content:
                    if detect["type"]!="Packer" and detect["type"]!="Protector":
                        continue
                    else:
                        if sample not in self.TD_samples:
                            self.TD_samples.append(sample)
                    if self.packer in sgname_normalize(detect['name']):
                        target = True
                    elif self.packer=="winupack" and "upack" in sgname_normalize(detect['name']):
                        target=True
                    elif self.packer=="beroexepacker" and "bero" in sgname_normalize(detect['name']):
                        target=True
                    else:
                        non_target = True
                if target:
                    self.TP_samples.append(sample)
                else:
                    self.FN_samples.append(sample)
                if non_target:
                    self.FP_samples.append(sample)
                else:          
                    self.TN_samples.append(sample)                  
            else:          
                self.FN_samples.append(sample)          
                self.TN_samples.append(sample)          
          
    def calcRatios(self):
        FP = len(self.FP_samples)
        FN = len(self.FN_samples)
        TP = len(self.TP_samples)
        TN = len(self.TN_samples)
        TD = len(self.TD_samples)
        self.FPR = FP*100 / (FP + TN)
        self.FNR = FN*100 / (FN + TP)
        self.TPR = TP*100 / (TP + FN)
        self.TNR = TN*100 / (TN + FP)
        self.TDR = TD*100/len(self.match_result)
    
    def analysis_output(self):
        if self.test_mode=="tagon":
            if self.configs["inaccessible_test"]:
                result_path="./result/inacc_lpd1.txt"
            else:
                result_path="./result/acc_lpd.txt"
            with open(result_path, "a") as f:
                f.write("DIE\n")
                f.write("\tFPR:"+"%.3g"%self.FPR+"\n")
                f.write("\tFNR:"+"%.3g"%self.FNR+"\n")
                f.write("\tTDR:"+"%.3g"%self.TDR+"\n")
                f.write("\ttime:"+ str(round(self.efficiency,2)) + "\n")
                f.write("\n")
        else:
            with open("./result/acc_npd.txt", "a") as f:
                f.write("-"*30 + "\n")
                f.write("----non pack test----\n")
                f.write(str(datetime.now())+"\n")
   
def DieMatchProcedure(IDieMatch:DieMatch):  
    IDieMatch.die_match()
    return os.path.join(IDieMatch.output_dir, IDieMatch.output_file)
    # IDieMatch.efficiency_output(IDieMatch.mode)

def judge_half(configs): 
    yara_json="./detection/non_pack/analysis/total_yara.json"
    die_json="./detection/non_pack/analysis/total_die.json"
    out_json="./detection/non_pack/analysis/result.json"
    with open(yara_json)as f1: 
        yara_result=json.load(f1)
    with open(die_json)as f2:
        die_result=json.load(f2)
    half_packed=[]
    packgenome_fp=[]
    artificial_fp=[]
    autoyara_fp=[]
    die_fp=[]
    for sample in yara_result[os.path.basename(configs["packgenome_rule"]).replace(".yar","_accessible.yar")]["FP_samples"]:
        half_packed.append(sample)
    for sample in die_result["FP_samples"]:
        half_packed.append(sample)
    for sample in yara_result[os.path.basename(configs["artificial_rule"])]["FP_samples"]:
        if sample not in half_packed:
            artificial_fp.append(sample)
    for sample in yara_result[os.path.basename(configs["autoyara_rule"]).replace(".yar","_accessible.yar")]["FP_samples"]:
        if sample not in half_packed:
            autoyara_fp.append(sample)
    
    judge_result={"packgenome":{"FP_number":len(packgenome_fp),"FP":packgenome_fp},"artificial":{"FP_number":len(artificial_fp),"FP":artificial_fp},"autoyara":{"FP_number":len(autoyara_fp),"FP":autoyara_fp},"die":{"FP_number":len(die_fp),"FP":die_fp}}
    with open(out_json,"w")as f3:
        f3.write(json.dumps(judge_result, indent=2)) 
    os.remove(yara_json)
    os.remove(die_json)
    npd_total=len(os.listdir(configs["NPD_testset"]))
    print("[+] " + os.path.basename(configs["packgenome_rule"]).replace(".yar","_accessible.yar"))
    print("    FPR: "+'%.3g'%(len(packgenome_fp)*100/npd_total))
    print("    TDR: "+'%.3g'%(len(packgenome_fp)*100/npd_total))
    print("[+] " +  os.path.basename(configs["artificial_rule"]))
    print("    FPR: "+'%.3g'%(len(artificial_fp)*100/npd_total))
    print("    TDR: "+'%.3g'%(len(artificial_fp)*100/npd_total))
    print("[+] " +  os.path.basename(configs["autoyara_rule"]).replace(".yar","_accessible.yar"))
    print("    FPR: "+'%.3g'%(len(autoyara_fp)*100/npd_total))
    print("    TDR: "+'%.3g'%(len(autoyara_fp)*100/npd_total))
    print("[+] DIE")
    print("    FPR: "+'%.3g'%(len(die_fp)*100/npd_total))
    print("    TDR: "+'%.3g'%(len(die_fp)*100/npd_total))
    with open("./result/acc_npd.txt", "a") as f:
        f.write("packgenome\n")
        f.write("\tFPR:"+'%.3g'%(len(packgenome_fp)*100/npd_total)+"\n")
        f.write("\tTDR:"+'%.3g'%(len(packgenome_fp)*100/npd_total)+"\n")
        f.write("\ttime:"+ str(yara_result[os.path.basename(configs["packgenome_rule"]).replace(".yar","_accessible.yar")]["time"]) + "\n")
        f.write("artificial\n")
        f.write("\tFPR:"+'%.3g'%(len(artificial_fp)*100/npd_total)+"\n")
        f.write("\tTDR:"+'%.3g'%(len(artificial_fp)*100/npd_total)+"\n")
        f.write("\ttime:"+ str(yara_result[os.path.basename(configs["artificial_rule"])]["time"]) + "\n")
        f.write("autoyara\n")
        f.write("\tFPR:"+'%.3g'%(len(autoyara_fp)*100/npd_total)+"\n")
        f.write("\tTDR:"+'%.3g'%(len(autoyara_fp)*100/npd_total)+"\n")
        f.write("\ttime:"+ str(yara_result[os.path.basename(configs["autoyara_rule"]).replace(".yar","_accessible.yar")]["time"]) + "\n")
        f.write("DIE\n")
        f.write("\tFPR:"+'%.3g'%(len(die_fp)*100/npd_total)+"\n")
        f.write("\tTDR:"+'%.3g'%(len(die_fp)*100/npd_total)+"\n")
        f.write("\ttime:"+ str(die_result["time"]) + "\n")
        f.write("\n")

def DieAnalysisProcedure(IDieAnalysis:DieAnalysis):
    analysis_output_dir=IDieAnalysis.output_dir+"analysis/"
    if not os.path.exists(analysis_output_dir):
        os.makedirs(analysis_output_dir)
    IDieAnalysis.analysis()
    if IDieAnalysis.test_mode=="tagon":
        IDieAnalysis.calcRatios()
    analysis_output_path= analysis_output_dir+IDieAnalysis.packer + IDieAnalysis.configs["die_output_suffix"]+".json"
    if IDieAnalysis.test_mode=="tagon":
        print("[+] DIE")
        print("    FPR: "+'%.3g'%IDieAnalysis.FPR)
        print("    FNR: "+'%.3g'%IDieAnalysis.FNR)
        print("    TDR: "+'%.3g'%IDieAnalysis.TDR)
        tmp_dict = {"FP_number":len(IDieAnalysis.FP_samples), "FP_samples":IDieAnalysis.FP_samples, "FN_number":len(IDieAnalysis.FN_samples), "FN_samples":IDieAnalysis.FN_samples}
    else:
        tmp_dict = {"FP_number":len(IDieAnalysis.FP_samples), "FP_samples":IDieAnalysis.FP_samples, "time":round(IDieAnalysis.efficiency,2)}
    with open(analysis_output_path, "w") as f:
        f.write(json.dumps(tmp_dict, indent=2))
    IDieAnalysis.analysis_output()
    os.removedirs
    return analysis_output_path    

def DieEvaluate(packer:str):
    with open("configs/EvaluationConfig.json", "r") as f:
        configs=json.load(f)
    MyMatch = DieMatch(packer = packer, configs=configs)
    json_matched_result=DieMatchProcedure(MyMatch)
    MyAnalysis = DieAnalysis(json_result= json_matched_result, packer = packer, configs=configs, efficiency=MyMatch.efficiency_result)
    analysis_output_path=DieAnalysisProcedure(MyAnalysis)
    if configs["test_mode"]=="non":
        judge_half(configs)
    return analysis_output_path

if __name__ == '__main__':
    DieEvaluate("fsg")