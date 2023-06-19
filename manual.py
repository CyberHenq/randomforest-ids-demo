"""manual.py prints the manual for the main program."""

#This program is free software: you can redistribute it and/or modify
#it under the terms of the GNU General Public License as published by
#the Free Software Foundation, either version 3 of the License, or
#(at your option) any later version.

#This program is distributed in the hope that it will be useful,
#but WITHOUT ANY WARRANTY; without even the implied warranty of
#MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#GNU General Public License for more details.

#You should have received a copy of the GNU General Public License
#along with this program.  If not, see <https://www.gnu.org/licenses/>.

def print_manual():
    print("\n"
            "  _______ _________ _______ _________ ______   _______  _______  _______  __   ______        _______  _______  _______  _______  _______ _________\n"
            " (  ____ \\\\__   __/(  ____ \\\\__   __/(  __  \\ (  ____ \\/ ___   )(   __  )/  \\ / ___  \\      (  ____ \\(  ___  )(  ____ )(  ____ \\(  ____ \\\\__   __/\n"
            " | (    \\/   ) (   | (    \\/   ) (   | (  \\  )| (    \\/\\/   )  ||  /  \\ |\\/) )\\/   )  )     | (    \\/| (   ) || (    )|| (    \\/| (    \\/   ) (   \n"
            " | |         | |   | |         | |   | |   ) || (_____     /   )|  |  | |  | |    /  /_____ | (__    | |   | || (____)|| (__    | (_____    | |   \n"
            " | |         | |   | |         | |   | |   | |(_____  )  _/   / |  |  | |  | |   /  /(_____)|  __)   | |   | ||     __)|  __)   (_____  )   | |   \n"
            " | |         | |   | |         | |   | |   ) |      ) | /   _/  |  |  | |  | |  /  /        | (      | |   | || (\\ (   | (            ) |   | |   \n"
            " | (____/\\___) (___| (____/\\___) (___| (__/  )/\\____) |(   (__/\|  \\__/ |__) (_/  /         | )      | (___) || ) \\ \\__| (____/\\/\\____) |   | |   \n"
            " (_______/\\_______/(_______/\\_______/(______/ \\_______)\\_______/(_______)\\____/\\_/          |/       (_______)|/   \\__/(_______/\\_______)   )_(   \n\n")

    print("An intrusion detection demo for my thesis that optimizes and uses a random forest model trained with the CICIDS2017 dataset. Anomaly detection focuses only on SSH-Patator detection.\n\n\n"
        "Usage: run.py [OPTION]\n\n"

        "[OPTION] flags are not mandatory.\n\n"
    
        "Available options:\n\n"

        "-e, --experiment:     Run the full optimization and analysis process for the random forest model. This can take a long time.\n"
        "-h, --help:           Show this help manual.\n"
        "-s, --sniffer:        Run the network sniffer. See cicids_rforest/sniff_ssh.py for the arguments.\n"
        "-v, --verbose:        Show useful debugging related information.\n\n"
        "CICIDS2017-Forest\n"
        "This program comes with ABSOLUTELY NO WARRANTY.\n"
        "This is free software, and you are welcome to redistribute it\n"
        "under certain conditions; see <https://www.gnu.org/licenses/> for details.\n")
