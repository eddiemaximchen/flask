安装
pip install click
使用
装饰一个函数，使之称为命令行接口
@click.command()
- 装饰函数，为其添加命令行选项
@click.option()
import click
@click.command()
@clcik.option("--count", default = 1, help = "Number")
@click.option("--name", prompt= "your name", help="The persion to greet.")
def hello(count, name):
  click.echo(count, name)

参数含义：

default: 设置命令行参数默认值
help: 参数说明
type: 参数类型，可以是string，int，float等
prompt:当在命令行中没有输入相应得参数时，会根据prompt提示用户输入
nargs: 指定命令行参数接受值得个数
metavar: 如何在帮助页面表示值
