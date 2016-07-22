cd ./web
start cmd /k python -m SimpleHTTPServer 8000
@echo off
set /p Username= Username-
set /p Password= Password-
set /p UserInputPath= Set Location-
cd ..
python main.py -u %Username% -p %Password% -l "%UserInputPath%"
pause
