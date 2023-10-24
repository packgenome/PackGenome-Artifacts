## Evaluation

Evaluation tool chain is used to compare PackGenome-generated rules with public-availabe packer signature collections (i.e., human-written YARA rules and Detect It Easy) and a state-of-the-art automatic YARA rule generation tool (i.e., AutoYara). 

### Requirement

- `AutoYara`-https://github.com/NeuromorphicComputationResearchProgram/AutoYara
- `Detect It Easy(3.06)`-https://github.com/horsicq/Detect-It-Easy

### Configuration

[Evaluation/EvaluationConfig.json](https://github.com/packgenome/PackGenome-Artifacts/blob/main/Evaluation/configs/EvaluationConfig.json) contains configuration options related to evaluation experiments. The key options excerpted from the configuration file are as follows.

```
"packgenome_rule": "", 			// Path of compiled PackGenome-genearted YARA rules
"artificial_rule": "",    	// Path of compiled collected human-written YARA rules
"autoyara_rule": "",				// Path of compiled AutoYara-genearted YARA rules
"test_mode": "",						// Evaluation mode: tagon/non
"thread": "8",							// Thread of yara test
"LPD_testset": "",					// Path of LPD dataset
"LPD1_testset": "",					// Path of LPD1 dataset
"NPD_testset": "",					// Path of NPD dataset
"accessible_packers": [],		// Off-the-shelf packers for evaluation 
"inaccessible_packers": []	// Inaccessible packers for evaluation 
```

### Experiments

We provide three evaluation experiments in this artifact.

- Matching off-the-shelf label packed programs

  LPD dataset contains non-malicious programs packed by 20 off-the-shelf packers. We calculate the FPR, FNR, TDR of all the rules on the LPD dataset.

  ```sh
  sh acc_eval.sh
  ```

- Matching inaccessible label packed programs

  LPD1 dataset contains non-malicious programs packed by 5 inaccessible packers. We calculate the FPR, FNR, TDR of all the rules on the LPD1 dataset.

  ```sh
  sh inacc_eval.sh

- Matching non-packed programs
  
  NPBD dataset contains real-world benign programs (e.g., system files), which extracted from the non-packed samples dataset NPD (including more than 20,000 malicious samples) described in our paper. We use the NPBD dataset to measure the false positives rate that rules mistakenly match the non-packed programs. We calculate the FPR, TDR of all the rules on the NPBD dataset.

  ```sh
  sh nonpack_eval.sh
  ```

After executing the above three command, `acc_lpd.txt`, `inacc_lpd1.txt` and `acc_npd.txt` will be generated in the `Evaluation/result` folder. `acc_lpd.txt` records the FPR, FNR, TDR of all tools for 20 off-the-shelf packers. `inacc_lpd1.txt` records the FPR, FNR, TDR of all tools for 5 inaccessible packers. `acc_npd.txt` records the FPR, TDR of all tools on the NPD dataset.

