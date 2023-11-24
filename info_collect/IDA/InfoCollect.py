import idautils
import ida_nalt
import yara
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


def analyze_str(yara_rule):

    ida_str = idautils.Strings()
    for info_str in ida_str:

        # 使用yara规则进行匹配
        matches = yara_rule.match(data=str(info_str))

        # 输出匹配结果
        if matches:
            for match in matches:

                # 判断该规则是否在dict中
                if match.rule in yara_resut:
                    yara_resut[match.rule].append(str(info_str))
                else:
                    yara_resut[match.rule] = []
                    yara_resut[match.rule].append(str(info_str))
    print(yara_resut)

if __name__ == "__main__":
    # 导入yara规则
    yara_rule = import_yara_rules()

    # 根据规则分析
    analyze_str(yara_rule)