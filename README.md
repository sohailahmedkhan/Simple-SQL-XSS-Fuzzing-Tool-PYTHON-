# Simple-SQL-XSS-Fuzzing-Tool-PYTHON-

This is a very basic Fuzzing tool, to fuzz the web applications with some predefined Static and then Dynamically generated Payloads. The tool is tested on a particular web application, and has statically defined endpoints to test, but it can be updated to crawl for the potential endpoints with little effort.

# Instructions to run the script

There are no special requirements to run my script. The only thing which is required is to have the provided payload text files and the fuzzer.py in the same directory.

The script writes the findings in a file named as summary_results.txt and that file will be created in the same directory as the fuzzer.py script.

The script prints the payloads for which the app is vulnerable, but to keep the output of the script in a tidy manner, I commented the print statements. If you want to see the payloads for which the app is vulnerable than you have to uncomment the print statements in the script.

I have commented those statements by #>>>>>>>>> symbols in the code so that they can be found easily.

# Remember to change the IP address with the IP of your server where you are running the Web Application, also, remember to change the statically defined endpoints with the endpoints of your own Web App. 
