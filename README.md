## PackGenome
<a href="https://github.com/packgenome/PackGenome-Artifacts/blob/main/Docs/CCS2023-PackGenome.pdf"><img alt="PackGenome thumbnail" align="right" width="300" src="https://github.com/packgenome/PackGenome-Artifacts/assets/87116389/6e828837-1864-4dea-b5fe-fbcaaed12927"></a>

Research Artifact for our **CCS 2023** paper: "PackGenome: Automatically Generating Robust YARA Rules for Accurate Malware Packer Detection"

To free security professionals from the burden of manually piecing together the tedious steps of packer signature generation, we developed PackGenome to generate YARA rules for accurate packer detection, and compared PackGenome-generated rules with public-available packer signature collections and state-of-the-art automatic rule generation tools. Evaluation results show that PackGenome outperforms existing work in all cases with zero false negatives, low false positives, and a negligible scanning overhead increase. More details are reported in our paper published at CCS 2023.

Paper: 
* [ACM Digital Library](https://dl.acm.org/doi/10.1145/3576915.3616625)
* [`Docs\CCS2023-PackGenome.pdf`](https://github.com/packgenome/PackGenome-Artifacts/blob/main/Docs/CCS2023-PackGenome.pdf)

Extended Paper: [`Docs\CCS2023-PackGenome-extended.pdf`](https://github.com/packgenome/PackGenome-Artifacts/blob/main/Docs/CCS2023-PackGenome-extended.pdf)

Artifact Appendix: [`Docs\artifact-appendix.pdf`](https://github.com/packgenome/PackGenome-Artifacts/blob/main/Docs/artifact-appendix.pdf)

Our artifact provides  source code, PackGenome-generated YARA rules, and datasets used in our experiments. To facilitate the usage of this artifact, we provide a [`Docker image`](https://zenodo.org/records/10030074/files/packgenome.tar) with the necessary component to execute the artifact. 

```
@inproceedings{li2023packgenome,
  title={PackGenome: Automatically Generating Robust YARA Rules for Accurate Malware Packer Detection},
  author={Li, Shijia and Ming, Jiang and Qiu, Pengda and Chen, Qiyuan and Liu, Lanqing and Bao, Huaifeng and Wang, Qiang and Jia, Chunfu},
  booktitle={Proceedings of the 2023 ACM SIGSAC Conference on Computer and Communications Security},
  pages={3078–3092},
  year={2023},
  location = {, Copenhagen, Denmark, }
}
```

## Prerequisites

### Hardware dependencies

We ran all experiments on a testbed machine with Intel i7-6700 CPU (4 cores, 3.40GHz), 32GB RAM, 1.8TB Hard Disk, running Windows 10. The AE reviewers can use more powerful hardware with more than 50 GB of disk space, because the size of our datasets is nearly 30 GB. To ease the AE committee to review, we omit the trace recording process and provide the recorded trace files in the [`Docker image`](https://zenodo.org/records/10030074/files/packgenome.tar) and repository ([Dataset/RGD](https://github.com/packgenome/PackGenome-Artifacts/tree/main/Dataset/RGD)). Because the trace recording process for all packed programs would takes more than 1 days. We provide the trace recorder in [MyPinTool](https://github.com/packgenome/PackGenome-Artifacts/tree/main/Pintool) folder and the [Generator/LogGeneration.py](https://github.com/packgenome/PackGenome-Artifacts/blob/main/Generator/LogGeneration.py) script. Without tracing, the whole evaluation takes roughly 3 hours.

### Software dependencies
```
- git
- python3 (3.7 or later version)
	- angr 9.2.6
	- plyara 2.1.1
- YARA 4.2.0
- Intel pin 3.12
- Detect It Easy 3.06
```
To reduce the workload of AE reviewers, we have packed all the required environment and software dependencies into the [`Docker image`](https://zenodo.org/records/10030074/files/packgenome.tar).
At least a Windows 10 system with `Docker` software is required.

### Dataset

Note that our paper extensively evaluated real-world Windows and Linux malware samples that take over 1 TB of disk space. To ensure the safety of the artifact evaluation process and to prevent any potential malicious or destructive operations, we have strictly provided non-malicious samples only.


All the datasets have packed into the docker image. We have also provided a [download link](https://mailnankaieducn-my.sharepoint.com/:u:/g/personal/1811387_mail_nankai_edu_cn/EYdZVCc4tk9AmSTwqb-HRYEBU4Bjw3d3B2M0fl859GLpcQ) for the datasets via OneDrive.

- **RGD: rule generation dataset**

  It contains programs packed by 20 popular off-the-shelf packers with multiple versions and configurations and 5 inaccessible packers. Each program corresponds to a trace file that records the unpacking routine instructions executed during program execution. 

	> Location in docker image: ``Dataset/RGD``.

- **LPD: labeled packed samples dataset**

  It contains non-malicious packed programs that can be linked to known packers (i.e., 20 off-the-shelf packers with multiple versions and configurations).

	> Location in docker image: ``Dataset/LPD``.

- **LPD1: inaccessible packer dataset**

   It contains non-malicious packed programs that can be linked to five inaccessible packers.

   > Location in docker image: ``Dataset/LPD1``.

- **NPBD: non-packed samples dataset**

  It contains real-world benign programs (e.g., system files), which extracted from the non-packed samples dataset NPD (including more than 20,000 malicious samples) described in our paper. 

  > Location in docker image: ``Dataset/NPBD``.

## Artifact Evaluation

### Installation: Import Docker Image

Download the packed [`Docker image`](https://zenodo.org/records/10030074/files/packgenome.tar), then run the commands below to build a docker container.

1. Import the packed docker image

   ```sh
   docker load packgenome.tar
   ```

2. Build a docker container.

   ```sh
   docker run -dit --name packgenome packgenome:v1 /bin/bash
   ```

3. Start an interactive docker shell for PackGenome.

   ```shell
   docker exec -it packgenome /bin/bash
   cd /home/Packgenome
   ```

### (E1): YARA Rule Generation [time required 20 minutes]

In this experiment, PackGenome generates YARA rules from 20 off-the-shelf packers with various versions and configurations provided in the [RGD dataset](https://github.com/packgenome/PackGenome-Artifacts/tree/main/Dataset/RGD). Given each configuration of packers, we generate three packed samples as input of packGenome. PackGenome extracts packer-specific genes from similar instructions reused in unpacking routines and transforms them into YARA rules. Find a detailed overview of trace recording process in [Generator/README.md](https://github.com/packgenome/PackGenome-Artifacts/blob/main/Generator/README.md).

We provide script [accrule_gen.sh](https://github.com/packgenome/PackGenome-Artifacts/blob/main/accrule_gen.sh) to run the YARA rules generation experiment:

```
sh accrule_gen.sh
```

Generated YARA rules for accessible packers would be stored in the `Generator/rules_dir` folder and named `accessible_rule.yar`. 

An example of UPX v3.9.6 detection rule generated by PackGenome is shown below. It is used to detect programs packed by UPX v3.96 that use nvr2b algorithm. 

```yara
import "pe"
import "dotnet"

rule packer_Upx_v396_nrv2b_1_combined
{
	meta:
		packer="Upx"
		generator="PackGenome"
		version="v396"
		configs="nrv2b_1 nrv2b_9 nrv2b_best"
	strings:
		$rule0 = {8a 07 47 2c e8 3c 01 77} 
		// mov al, byte ptr [edi]; inc edi; sub al, 0xe8; cmp al, 1; ja 0x41cf4a;  
		$rule1 = {8a 06 46 88 07 47 01 db 75} 
		// mov al, byte ptr [esi]; inc esi; mov byte ptr [edi], al; inc edi; add ebx, ebx; jne 0x41ce99;  
		$rule2 = {11 c0 01 db 73} 
		// adc eax, eax; add ebx, ebx; jae 0x41cea0;  
		$rule3 = {8b 02 83 c2 04 89 07 83 c7 04 83 e9 04 77} 
		// mov eax, dword ptr [edx]; add edx, 4; mov dword ptr [edi], eax; add edi, 4; sub ecx, 4; ja 0x41cf2c;  
		$rule4 = {b8 01 00 00 00 01 db 75} 
		// mov eax, 1; add ebx, ebx; jne 0x41ceab;  
		$rule5 = {31 c9 83 e8 03 72} 
		// xor ecx, ecx; sub eax, 3; jb 0x41ced0;  
		$rule6 = {11 c9 01 db 75} 
		// adc ecx, ecx; add ebx, ebx; jne 0x41cee8;  
		$rule7 = {c1 e0 08 8a 06 46 83 f0 ff 74} 
		// shl eax, 8; mov al, byte ptr [esi]; inc esi; xor eax, 0xffffffff; je 0x41cf42;  
		$rule8 = {89 c5 01 db 75} 
		// mov ebp, eax; add ebx, ebx; jne 0x41cedb;  
		$rule9 = {81 fd 00 f3 ff ff 83 d1 01 8d 14 2f 83 fd fc 76} 
		// cmp ebp, 0xfffff300; adc ecx, 1; lea edx, [edi + ebp]; cmp ebp, -4; jbe 0x41cf2c;  
		$rule10 = {41 01 db 75} 
		// inc ecx; add ebx, ebx; jne 0x41cef8;  
		$rule11 = {83 c1 02 81 fd 00 f3 ff ff 83 d1 01 8d 14 2f 83 fd fc 76} 
		// add ecx, 2; cmp ebp, 0xfffff300; adc ecx, 1; lea edx, [edi + ebp]; cmp ebp, -4; jbe 0x41cf2c;  
		$rule12 = {8a 02 42 88 07 47 49 75} 
		// mov al, byte ptr [edx]; inc edx; mov byte ptr [edi], al; inc edi; dec ecx; jne 0x41cf1d;  
		$rule13 = {8b 07 8a 5f 04 66 c1 e8 08 c1 c0 10 86 c4 29 f8 80 eb e8 01 f0 89 07 83 c7 05 88 d8 } 
		// mov eax, dword ptr [edi]; mov bl, byte ptr [edi + 4]; shr ax, 8; rol eax, 0x10; xchg ah, al; sub eax, edi; sub bl, 0xe8; add eax, esi; mov dword ptr [edi], eax; add edi, 5; mov al, bl; loop 0x41cf4f;  
		$rule14 = {8b 1e 83 ee fc 11 db 72} 
		// mov ebx, dword ptr [esi]; sub esi, -4; adc ebx, ebx; jb 0x41ce88;  
		$rule15 = {8b 1e 83 ee fc 11 db 11 c0 01 db 73} 
		// mov ebx, dword ptr [esi]; sub esi, -4; adc ebx, ebx; adc eax, eax; add ebx, ebx; jae 0x41cea0;  
		
	condition:
		pe.is_32bit() and (11 of them) and (pe.overlay.offset == 0 or for 7 of ($*) : (@ < pe.overlay.offset)) and (not dotnet.is_dotnet)
}
```

### (E2): Comparison on LPD [time required 2 hours]

This experiment comparing PackGenome-generated rules with public-available packer signature collections and a state-of-the-art automatic rule genertion tool ([AutoYara](https://github.com/NeuromorphicComputationResearchProgram/AutoYara)) on the LPD dataset. We provide compiled YARA rules (located at [Evaluation/YaraRules](https://github.com/packgenome/PackGenome-Artifacts/tree/main/Evaluation/yaraRules)) for evaluation to save time. According to YARA’s documentation, it is faster for YARA to load compiled rules than compiling the same rules over and over again.

Run the command below to repeat this experiment:

```
sh acc_eval.sh
```

We calculate the FPR, FNR, TDR of all rules on the LPD dataset. The evaluation result would be stored in the `Evaluation/result/acc_lpd.txt` .

An example of evaluation results for UPX packed samples is as follows:

```
------------------------------
2023-10-19 16:48:59.637828
[+]upx
packgenome_accessible.yarc
	FPR:0
	FNR:0
	TDR:100
	time:0.87
artificial.yarc
	FPR:100
	FNR:0
	TDR:100
	time:2.23
autoyara_accessible.yarc
	FPR:22.7
	FNR:68
	TDR:41.1
	time:0.65
DIE
	FPR:0
	FNR:0
	TDR:100
	time:306.76
```

In the above example, both PackGenome-generated rules and Detect It Easy accurately identify all programs packed by UPX in the LPD dataset with no false positives and false negatives. And PackGenome-generated rules take less time compared to Detect It Easy. Public-available human-written packer detection rules suffers from a high false positive. As for AutoYara, it doesn't work well for packed programs.

### (E3): Comparison on NPBD [time required 10 minutes]

This experiment compare PackGenome-generated rules with human-written rules, AutoYara, and DIE on the NPBD dataset. We also provide compiled YARA rules (located at [Evaluation/YaraRules](https://github.com/packgenome/PackGenome-Artifacts/tree/main/Evaluation/yaraRules)) for evaluation to save time. 

Run the command below to repeat this experiment:

```
sh nonpack_eval.sh
```

We calculate the FPR, TDR of all rules on the NPBD dataset. The evaluation result would be stored in the `Evaluation/result/acc_npd.txt` .

### (E4): Comparison on LPD1 [time required 10 minutes]

PackGenome can also generate YARA rules for old packers that are no longer available in the market and custom packers written by malware authors. In this experiment, PackGenome generates YARA rules for 5 inaccessible packers and compare PackGenome-generated rules with other rules on the LPD1 dataset.

Run the command  below to generate YARA rules for 5 inaccessible packers and evaluate generated YARA rules on the LPD1 dataset.

```
sh inaccrule_gen.sh
sh inacc_eval.sh
```

Generated YARA rules would be stored in the `Generator/rules_dir` folder and named `inaccessible_rule.yar`. The validation result would be stored in the `Evaluation/result` folder with a file name`inacc_lpd1.txt`.

## Code Structure

```
├── Pintool/							// Pin tools' source code
├── Generator/							// scripts for YARA rules generation
├── Evaluation/							// scripts for main evaluation 
├── Dataset/							// dataset for main evaluation
├── accrule_gen.sh						// script for 20 accessible packers' YARA rules generation 
├── inaccrule_gen.sh						// script for 5 inaccessible packers' YARA rules generation 
├── acc_eval.sh							// script for evaluation on LPD dataset
├── inacc_eval.sh						// script for evaluation on LPD1 dataset
├── nonpack_eval.sh						// script for evaluation on NPBD dataset
```

