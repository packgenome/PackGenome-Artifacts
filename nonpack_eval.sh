# Comparing PackGenome-generated accessible packer detection rules with other YARA rules and DIE on the bengin non-packed sample dataset

CUR_DIR=$PWD
cd $CUR_DIR/Evaluation/
python3 callerToYaraEva.py -m non
