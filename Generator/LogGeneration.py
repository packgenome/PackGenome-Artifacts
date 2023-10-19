#!/usr/bin/env python3
# -*- encoding: utf-8 -*-

import sys, getopt
import os
import json
from PreAnalysis import *
from BytesAnalysis import *

# generate a json file recording samples' information (path include versions, configs and filenames)
def samples_extract(testpackers, rootpath, inaccessibleTest, dumpname=""):
    result = []
    for packer in os.listdir(rootpath):
        if packer.lower() in testpackers:
            tmp_dict = {}
            tmp_dict["name"] = packer
            if inaccessibleTest:
                tmp_dict["samples"]=[]
                for sample in os.listdir(rootpath+packer+"/"):
                    if sample.endswith(".exe"):
                        tmp_dict["samples"].append(sample)
            else:
                tmp_dict["versions"] = {}
                for version in os.listdir(os.path.join(rootpath, packer)):
                    tmp_dict["versions"][version] = {}
                    v = os.path.join(rootpath, packer, version)
                    configs = os.listdir(v)
                    for cf in configs:
                        p = os.path.join(v, cf)
                        if os.path.isdir(p):
                            for file in os.listdir(p):
                                if packer.lower() in ["fsg", "mew", "mpress", "armadillo","winupack","pecompact","pelock", "petite"]: # 这几类packer加壳后默认是.exe
                                    filend = ".exe"
                                elif packer.lower() in ["expressor"]:
                                    filend = "Pk.exe"
                                else:
                                    filend = "_packed.exe"
                                if file.endswith(filend):
                                    if cf not in tmp_dict["versions"][version].keys():
                                        tmp_dict["versions"][version][cf] = [file]
                                    else:
                                        tmp_dict["versions"][version][cf].append(file)
            result.append(tmp_dict)
    if dumpname:
        f = open(os.path.join("./", dumpname), "w")
        f.write(json.dumps(result, indent=4))
    return result

def jsonfiles_extract(result_json, root_dir, customTest, dumpname):
    json_location = []
    for packer in result_json:
        tmp_dict = {}
        packername = packer["name"]
        tmp_dict["name"] = packername
        # inaccessible: {"name":packername, "jsonfiles":jsonfiles, "errorfiles":errorfiles}
        if customTest:
            filepath = filepath = os.path.join(root_dir, packername)
            jsonfiles = []
            errorfiles = []
            if os.path.isdir(filepath):
                for file in os.listdir(filepath):
                    if file.endswith(".json"):
                        p = os.path.join(filepath, file)
                        with open(p, "r") as f:
                            tmpjson = json.load(f)
                            if len(tmpjson) == 3:
                                print("[-] Empty: " + p)
                                errorfiles.append(p)
                            else:
                                jsonfiles.append(p)
            tmp_dict["jsonfiles"] = jsonfiles
            tmp_dict["errorfiles"] = errorfiles
        # accessible: {"name":packername, "versions":{"v1": {"config1":[], "config2":[]}, "v2": {"config1":[], "config2":[]}}}
        else:
            errorfiles = []
            tmp_dict["versions"] = {}
            for version in packer["versions"]:
                tmp_dict["versions"][version] = {}
                for config in packer["versions"][version]:
                    filepath = os.path.join(root_dir, packername, version, config)
                    tmp_dict["versions"][version][config] = []
                    if os.path.isdir(filepath):
                        for file in os.listdir(filepath):
                            if file.endswith(".json"):
                                p = os.path.join(filepath, file)
                                with open(p, "r") as f:
                                    tmpjson = json.load(f)
                                    if len(tmpjson) == 3:
                                        #print("[-] Empty: " + p)
                                        errorfiles.append(p)
                                    else:
                                        tmp_dict["versions"][version][config].append(p)
        json_location.append(tmp_dict)
    if dumpname:
        #print(os.path.join("./", dumpname+".json"))
        f = open(os.path.join("./", dumpname+".json"), "w")
        f.write(json.dumps(json_location, indent=4))
    return json_location

def clean_logs(samples_dir):
    for sample in os.listdir(samples_dir):
        sample_path=os.path.join(samples_dir,sample)
        if ".exe" not in sample_path:
            os.remove(sample_path)
    
def log_generate_all():
    with open("./config/GenConfig.json")as f:
        configs=json.load(f)
    #updateJson
    if configs["updateJson"]:
        if configs["inaccessibleTest"]:
            result_json = samples_extract(configs["inaccessible_packers"],configs["inaccessible_dir"], True, configs["inaccessible_contents"])
        else:
            result_json = samples_extract(configs["accessible_packers"],configs["accessible_dir"], False, configs["accessible_contents"])
    else:
        if configs["inaccessibleTest"]:
            with open(configs["inaccessible_contents"]) as f:
                result_json = json.load(f)
        else:
            with open(configs["accessible_contents"]) as f:
                result_json = json.load(f)
    for packer in result_json:
        packername = packer["name"]
        print("[+] " + packername)
        if not configs["inaccessibleTest"]:
            for version in packer["versions"]:
                for cf in packer["versions"][version].keys():
                    filepath = os.path.join(configs["accessible_dir"], packername, version, cf)
                    samples=packer["versions"][version][cf]
                    log_generate(configs,filepath,samples)
        else:
            filepath=os.path.join(os.path.join(configs["inaccessible_dir"], packername))
            samples=packer["samples"]
            log_generate(configs,filepath,samples)

def log_generate(configs,samples_dir,samples):
    #preanalysis
    if configs["preanalysis"]:
        print("    preAnalysis: " + samples_dir)
        for sample in samples:
            outputFile(GetInterestingSection(os.path.join(samples_dir, sample), CPA_mode=False), samples_dir+"/"+os.path.splitext(sample)[0])
    #pin log
    if configs["pin"]:
        pintool_dir=os.path.abspath("../Pintool")
        print("pintool:",pintool_dir)
        if configs["x64"]:
            pintool = os.path.join(pintool_dir,"MyPinTool64.dll")
        else:
            pintool = os.path.join(pintool_dir,"MyPinTool.dll")
        print("    Generate logs by Pintool: " + samples_dir)
        for sample in samples:
            log =  os.path.join(samples_dir, os.path.splitext(sample)[0] + ".prelog")
            res = os.path.join(samples_dir, sample)
            print(f"pin -t {pintool} -i {log} -- {res}")
            os.system(f"pin -t {pintool} -i {log} -- {res}")
            os.system("move {l} {o}".format(l = os.path.splitext(sample)[0] + ".log", o = samples_dir))
    #bytes_analysis
    if configs["bytes_analysis"]:
        print("    BytesAnalysis: " + samples_dir)
        for sample in samples:
            filename = os.path.splitext(sample)[0]
            log_path = os.path.join(samples_dir, filename + ".log")
            resultLog = logFormating(log_path)
            resultBytes = FindStaticBytes(os.path.join(samples_dir, sample), resultLog)
            result = filterItems(resultBytes)
            byteSortFile(result, filename, True, samples_dir)

if __name__ == "__main__":
    log_generate_all()
