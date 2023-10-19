import json
from YaraEvaluate import YaraEvaluate
from DieEvaluate import DieEvaluate
import optparse
from datetime import datetime
from time import time
import os

if __name__ == '__main__':
    if not os.path.exists("./result"):
        os.mkdir("./result")
    if not os.path.exists("./detection"):
        os.mkdir("./detection")
    starttime=time()
    oParser = optparse.OptionParser(usage='usage: %prog \n')
    oParser.add_option('-m', '--mode', default="tagon") 
    oParser.add_option('-o', '--optional', action="store_true") 
    oParser.add_option('-i', '--inaccessible', action="store_true")
    (options, args) = oParser.parse_args() 

    with open("./configs/EvaluationConfig.json", "r") as f:
        configs = json.load(f)
    configs["test_mode"]=options.mode
    configs["other_tools_test"]=options.optional
    configs["inaccessible_test"]=options.inaccessible
    with open("./configs/EvaluationConfig.json", "w") as f:
        f.write(json.dumps(configs,indent=2))

    if configs["test_mode"]=="tagon":
        print(f"-------- Tag On Test --------")
        if configs["inaccessible_test"]:
            for packer in configs["inaccessible_packers"]:
                print(f"-------- {packer} Test --------")
                YaraEvaluate(packer)
                DieEvaluate(packer)
        else:
            for packer in configs["accessible_packers"]:
                print(f"-------- {packer} Test --------")
                YaraEvaluate(packer)
                if not configs["other_tools_test"]:
                    DieEvaluate(packer)
    else:#non pack
        print(f"-------- None pack Test --------")
        YaraEvaluate("total")
        DieEvaluate("total")
    print("Total time:"+str(time()-starttime))
