import yara
import r2pipe
import sys
import json
import os

yara_resut = dict()

def import_yara_rules():
    # 指定包含YARA规则的文件路径
    rule_file_path = os.path.join("..", "rules", "index.yara")

    # 获取当前脚本所在的目录
    script_dir = os.path.dirname(os.path.abspath(__file__))

    # 获取文件的绝对路径
    file_path = os.path.abspath(os.path.join(script_dir, rule_file_path))

    # 从文件中加载YARA规则
    compiled_rules = yara.compile(filepath=file_path)

    # YARA规则反弹
    return compiled_rules


def analyze_str(yara_rule, binary_file):
    r = r2pipe.open(binary_file)
    json_out = r.cmd('izzj') # get import table as json

    # 将字典转换为JSON格式的字符串
    json_dict= json.loads(json_out)

    for data in json_dict:

        extract_string = data["string"]

        matches = yara_rule.match(data=extract_string)

        # 输出匹配结果
        if matches:
            for match in matches:

                # 判断该规则是否在dict中
                if match.rule in yara_resut:
                    yara_resut[match.rule].append(extract_string)
                else:
                    yara_resut[match.rule] = []
                    yara_resut[match.rule].append(extract_string)
    print(yara_resut)

if __name__ == "__main__":
    # 获取带分析的程序
    binary_file = sys.argv[1]

    # 导入yara规则
    yara_rule = import_yara_rules()

    # 根据规则分析
    analyze_str(yara_rule, binary_file)