# 导入必要的模块
from ghidra.program.model.listing import Data
from ghidra.program.model.scalar import Scalar
from ghidra.util.task import TaskMonitor

import os

# yara规则分析库
import yara

yara_resut = dict()

# 判断一个变量是否为字符串类型
def is_string(var):
    return isinstance(var, str)

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
    # 获取当前程序
    currentProgram = getCurrentProgram()

    # 获取所有数据
    dataIterator = currentProgram.getListing().getDefinedData(True)

    # 遍历数据并筛选字符串
    for data in dataIterator:

        # 检查数据类型是否为字符串类型
        if is_string(data.getValue()):

            # 使用yara规则进行匹配
            matches = yara_rule.match(data=data.getValue())

            # 输出匹配结果
            if matches:
                for match in matches:

                    # 判断该规则是否在dict中
                    if match.rule in yara_resut:
                        yara_resut[match.rule].append(data.getValue())
                    else:
                        yara_resut[match.rule] = []
                        yara_resut[match.rule].append(data.getValue())

    print(yara_resut)


if __name__ == "__main__":
    # 导入yara规则
    yara_rule = import_yara_rules()

    # 根据规则分析
    analyze_str(yara_rule)
