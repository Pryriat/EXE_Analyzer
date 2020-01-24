# EXE_Analyzer
简易程序行为分析工具

# 功能
- [x] 反调试（\*仅针对IsDebuggerPresent)
- [x] 文件类API调用跟踪
- [x] 进程类API调用跟踪
- [ ] 网络类API调用跟踪
- [x] 注册表类API调用跟踪
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

# 示例输出
```
2020-01-24 18:19:00,293 - CreateFile->FileName:C:\pagefile.sys
2020-01-24 18:19:00,309 - Load:C:\WINDOWS\system32\uxtheme.dll
2020-01-24 18:19:00,325 - CreateProcess->Handle:, CommandLine:@WanaDecryptor@.exe co
2020-01-24 18:19:00,341 - Load:C:\WINDOWS\system32\apphelp.dll
2020-01-24 18:19:00,341 - CreateFile->FileName:00000000.res
2020-01-24 18:19:00,371 - CreateProcess->Handle:, CommandLine:cmd.exe /c start /b @WanaDecryptor@.exe vs
2020-01-24 18:19:00,388 - CreateFile->FileName:C:\Users\hjc\AppData\Local\Temp\hibsys.WNCRYT
2020-01-24 18:19:16,200 - CreateFile->FileName:00000000.res
2020-01-24 18:19:28,740 - CreateProcess->Handle:, CommandLine:taskdl.exe
2020-01-24 18:19:29,223 - CreateProcess->Handle:, CommandLine:taskse.exe C:\Users\hjc\Desktop\@WanaDecryptor@.exe
2020-01-24 18:19:29,239 - CreateProcess->Handle:, CommandLine:@WanaDecryptor@.exe
2020-01-24 18:19:29,239 - CreateProcess->Handle:, CommandLine:cmd.exe /c reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run /v "yifyuubai741" /t REG_SZ /d "\"C:\Users\xxx\Desktop\tasksche.exe\"" /f
2020-01-24 18:19:41,645 - CreateFile->FileName:00000000.res
2020-01-24 18:19:58,957 - CreateProcess->Handle:, CommandLine:taskdl.exe
2020-01-24 18:19:59,506 - CreateProcess->Handle:, CommandLine:taskse.exe C:\Users\xxx\Desktop\@WanaDecryptor@.exe
2020-01-24 18:19:59,506 - CreateProcess->Handle:, CommandLine:@WanaDecryptor@.exe
2020-01-24 18:20:07,145 - CreateFile->FileName:00000000.res
2020-01-24 18:20:29,880 - CreateProcess->Handle:, CommandLine:taskdl.exe
2020-01-24 18:20:29,895 - CreateProcess->Handle:, CommandLine:taskse.exe C:\Users\xxx\Desktop\@WanaDecryptor@.exe
2020-01-24 18:20:29,911 - CreateProcess->Handle:, CommandLine:@WanaDecryptor@.exe
2020-01-24 18:20:32,770 - CreateFile->FileName:00000000.res
2020-01-24 18:20:58,164 - CreateFile->FileName:00000000.res
2020-01-24 18:21:00,101 - CreateProcess->Handle:, CommandLine:taskse.exe C:\Users\xxx\Desktop\@WanaDecryptor@.exe
2020-01-24 18:21:00,101 - CreateProcess->Handle:, CommandLine:@WanaDecryptor@.exe
2020-01-24 18:21:00,148 - CreateProcess->Handle:, CommandLine:taskdl.exe
2020-01-24 18:21:23,710 - CreateFile->FileName:00000000.res
2020-01-24 18:21:30,381 - CreateProcess->Handle:, CommandLine:taskse.exe C:\Users\xxx\Desktop\@WanaDecryptor@.exe
2020-01-24 18:21:30,397 - CreateProcess->Handle:, CommandLine:@WanaDecryptor@.exe
2020-01-24 18:21:30,506 - CreateProcess->Handle:, CommandLine:taskdl.exe
2020-01-24 18:21:49,326 - CreateFile->FileName:00000000.res
```
# 第三方模块及参考：
- [winappdbg](https://winappdbg.readthedocs.io/en/latest/)




