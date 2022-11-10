1) git clone https://github.com/beastmodeswag/FYP-IDS.git
2) cd FYP-IDS

# Create a virtual environment(To ensure the dependencies do not affect other python programs)
3) python3.10 -m venv venv  #or whichever version of python you ahve running(e.g 'python3.9 -m venv venv')

*If you need to install venv use : 'sudo apt install python3.10-venv'

# Activate that virtual environment
4) source venv/bin/activate   #If there are errors check the directory(e.g 'source /bin/activate' instead)

# Install the project requirements.
5) pip install -r requirements.txt

#change the localhost_ip in main.py
6) change the variable 'localhost_ip' with your ip

# To run the program(requires sudo)
7) sudo python main.py

# An ip address should show up on the terminal(e.g http://127.0.0.1:5050)


*Remember to change the host address in the config.txt file to your ip address


*Note: May not work on windows systems as the packet sniffer is set to sniff packets for unix-based systems

# Config telegram bot to send message to you
1. Search for LixDetector bot on telegram
2. Send a message in the LixDetector chat
3. Visit https://api.telegram.org/bot5623414566:AAGKkS-1jP2mWgCSYVkSkMDs9QmvLnmaegU/getUpdates 
4. Copy the the value in the id parameter
5. Update the send_to_telegram function's chatID variable with the id value copied from before
