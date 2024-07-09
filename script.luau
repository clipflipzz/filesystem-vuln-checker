local passes = 0
local fails = 0
local notest = 0
local running = 0
local exploitname = identifyexecutor() or getexecutorname() or executorname() or function() return 'Unknown' end

print(" \n")
print("File System Vulnerability Check - Executor: " .. tostring(exploitname))
print("✅ - Pass, ⛔ - Fail, ⏺️ - No test\n")

task.spawn(function()
    repeat game:GetService("RunService").Heartbeat:Wait() until running == 0

    local rate = math.round(fails / (fails + passes) * 100)
    local outOf = passes .. " out of " .. (passes + fails)
    local total = passes + fails + notest
    print("\n")
    print("File System Vulnerability Check Summary - " .. tostring(exploitname))
        print("✅ " .. rate .. "% vulnerabilities mitigated (".. fails.. " out of ".. total.. ")")
    print("⛔ ".. outOf.. " not mitigated vulnerabilities")
    print("⏺️ " .. notest .. " vulnerabilities not tested")
    print("This appears to be everything. For other potential vulnerabilities, join dsc.gg/clipflip.")
end)

for _,s in pairs({
    {name = 'Writefile for .py', callback = function()
        writefile("Test.py", "test")
        if isfile("Test.py") then 
            assert("Bad actors can execute python code, even potential RATs")
        end
    end},
    {name = 'Writefile for .exe', callback = function()
        writefile("Test.exe", "test")
        if isfile("Test.exe") then 
            assert("It's easy to see how this can be dangerous")
        end
    end},
    {name = 'Writefile for .bat', callback = function()
        writefile("Test.bat", "test")
        if isfile("Test.bat") then 
            assert("Bad actors are able to execute any Batch code")
        end
    end},
    {name = 'Writefile for .cmd', callback = function()
        writefile("Test.cmd", "test")
        if isfile("Test.cmd") then 
            assert("Cmd is equal to .bat, so bad actors can execute any batch code")
        end
        
    end},
    {name = 'Writefile for .pyc', callback = function()
        writefile("Test.pyc", "test")
        if isfile("Test.pyc") then 
        assert("Pyc is compiled Python code, even tho hard to implement, possbile RCE")
        end
    end},
    {name = 'Writefile for .dll', callback = function()
        writefile("Test.dll", "test")
        if isfile("Test.dll") then 
        assert("Dll allows for Dynamic Linking and is also an application, even tho hard, but possible RCE")
        end
    end},
    {name = 'Writefile for .apk', callback = function()
        writefile("Test.apk", "test")
        if isfile("Test.apk") then 
        assert("Even tho only applicable for phones, still possible RCE")
        end
    end},
    {name = 'Writefile for .abb', callback = function()
        writefile("Test.abb", "test")
        if isfile("Test.abb") then 
        assert("Modern version of Apk")
        end
    end},
    {name = 'Writefile for .appx', callback = function()
        writefile("Test.appx", "test")
        if isfile("Test.appx") then 
        assert("UWP Installer file, potential RCE")
        end
    end},
    {name = 'Writefile for .msi', callback = function()
        writefile("Test.msi", "test")
        if isfile("Test.msi") then 
        assert("Msi is a Microsoft Installer file format, possible RCE")
        end
    end},
    {name = 'Writefile for .jar', callback = function()
        writefile("Test.jar", "test")
        if isfile("Test.jar") then 
        assert("JAVA file format, potential RCE with Java applications")
        end
    end},
    {name = 'Writefile for .vbs', callback = function()
        writefile("Test.vbs", "test")
        if isfile("Test.vbs") then 
        assert("Potential RCE with Visual Basic applications")
        end
    end},
    {name = 'Writefile for .ps1', callback = function()
        writefile("Test.ps1", "test")
        if isfile("Test.ps1") then 
        assert("Bad actors can execute Powershell code")
        end
    end},
}) do
    running = running + 1
    local serviceName, methodName = s.name:match('game:GetService%("([^"]+)"%):([^"]+)%(%)')
    local success, message

    if not methodName then methodName = s.name end

    if methodName then
        success, message = pcall(s.callback)
        if type(message) == "function" then message = nil end
    end

    if message == "Executor does not support function" then
        notest = notest + 1
        print("⏺️ " .. methodName .. (message and " • " .. message or ""))
    else
        if success then
            passes = passes + 1
            warn("⛔ " .. methodName .. ": Vulnerability not mitigated")
            wait(1)
        else
            fails = fails + 1
            print("✅ " .. methodName .. " is mitigated: " .. message)
            wait(1)
        end
    end
    running = running and running - 1
end
