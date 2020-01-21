# EXE_Analyzer
简易程序行为分析工具

# 功能
- [x] 反调试（\*仅针对IsDebuggerPresent)
- [x] 文件类API调用跟踪
- [x] 进程类API调用跟踪
- [ ] 网络类API调用跟踪
- [ ] 注册表类API调用跟踪
- [ ] 杂项API调用跟踪
- [ ] 基于PyQt5的GUI

# 使用方法

- ```python
    python run.py C:\Example.exe
  ```
- 运行后分析数据存储于`run.py`目录下的`my.log`

# 注意事项
- 只适用于windows xp 以上的x86系统
- python 2.7

# 第三方模块及参考：
- [winappdbg](https://winappdbg.readthedocs.io/en/latest/)




