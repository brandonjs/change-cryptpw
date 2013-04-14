// change-cryptpw

#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <fstream>
#include <sstream>
#include <tcl8.3/expect.h>
#include <termios.h>
using namespace std;

void sigfun(int sig)
{
   cout << "This script cannot be killed." << endl;
}

void closeCrypt(string cryptainer)
{
    int exitStatus = 255;
    char cmd[128];
    sprintf(cmd, "cryptsetup luksClose %s > /dev/null 2>&1", cryptainer.c_str());
    exitStatus = system(cmd);
    exitStatus = WEXITSTATUS(exitStatus);
    if ( exitStatus != 0 && exitStatus != 237) {
       sleep(1);
       system(cmd);
   }
}

int encryptAdd(char* cmd, string oldkey, string cryptkey) {
    string key1 = oldkey;
    string key2 = cryptkey;
    key1 = key1 + "\r\n";
    key2 = key2 + "\r\n";

    exp_is_debugging  = 0;
#ifdef DEBUG
    exp_is_debugging  = 1;
#endif
    exp_loguser       = 0;
    exp_timeout       = 10; // timeout in seconds

    FILE* fp = exp_popen(cmd);
    if (fp == NULL) return 1;

    // get the file descriptor
    int fd = fileno(fp);
    int result = 255, passwordSet = 0;

    while (!passwordSet) {
      result = exp_expectl(fd,
         exp_glob, "*any passphrase*: ", 0,
         exp_glob, "*new passphrase for key slot:*", 1,
         exp_glob, "*Verify passphrase:*", 2,
         exp_end);

      switch (result)
      {
         case EXP_TIMEOUT:
#ifdef DEBUG
            printf("Got a timeout\n");
#endif
         break;
         case 2:
#ifdef DEBUG
            printf("Got prompt for password verify.\n");
#endif
            write(fd, key2.c_str(), strlen(key2.c_str()));
         break;
         case 1:
#ifdef DEBUG
            printf("Got prompt for new password.\n");
#endif
            write(fd, key2.c_str(), strlen(key2.c_str()));
         break;
         case 0:
#ifdef DEBUG
            printf("Got prompt for old password.\n");
#endif
            write(fd, key1.c_str(), strlen(key1.c_str()));
         break;
         default:
#ifdef DEBUG
            printf("This should be a prompt.\n");
#endif
            passwordSet = 1;
         break;
      } /* end switch */
   } /* end while */
   pclose(fp);
   return 0;
}

int encryptKill(char* cmd, string cryptkey) {
    string key1 = cryptkey;
    key1 = key1 + "\r\n";

    exp_is_debugging  = 0;
#ifdef DEBUG
    exp_is_debugging  = 1;
#endif
    exp_loguser       = 0;
    exp_timeout       = 10; // timeout in seconds

    FILE* fp = exp_popen(cmd);
    if (fp == NULL) return 1;

    // get the file descriptor
    int fd = fileno(fp);
    int result = 255, slotKill = 0;

    while (!slotKill) {
      result = exp_expectl(fd,
         exp_glob, "*Enter any remaining LUKS passphrase*: ", 0,
         exp_end);

      switch (result)
      {
         case EXP_TIMEOUT:
#ifdef DEBUG
            printf("Got a timeout\n");
#endif
         break;
         case 0:
#ifdef DEBUG
            printf("Got prompt for any remaining password.\n");
#endif
            write(fd, key1.c_str(), strlen(key1.c_str()));
         break;
         default:
#ifdef DEBUG
            printf("This should be a prompt.\n");
#endif
            slotKill = 1;
         break;
      } /* end switch */
   } /* end while */
   pclose(fp);
   return 0;
}

string exec(char* cmd) {
    FILE* pipe = popen(cmd, "r");
    if (!pipe) return "ERROR";
    char buffer[128];
    string result = "";
    while(!feof(pipe)) {
        if(fgets(buffer, 128, pipe) !=  NULL)
                result += buffer;
    }
    pclose(pipe);
    return result;
}

int main ()
{
    char cmd[128];
    char usepw[128] = "";
    char defpw[] = { 'q', 'u', 'a', 'l', 'c', 'o', 'm', 'm', '1', '\0' };
    char dfspw[] = { 'L', '@', '|', '>', 't', 'o', 'p', 'd', 'r', '0', 'p', '\0' };
    char engpw[] = { '|', '_', '|', 'b', 'u', 'n', 't', 'u', '!', '\0' };
    char secpw[] = { '$', '3', 'c', 'u', 'r', 'e', 'c', 'r', 'y', '|', '>', 'T', '\0' };
    string defchk = "pwchk", cryptstring, cryptpart;
    int exitStatus = 255, changeSec = 0, changeEng = 0, changeDfs = 0;
    ifstream inp;

    if (getuid() != 0 || geteuid() != 0) {
      fprintf(stderr, "This script must be run as root\n");
      return 1;
    }

    (void) signal(SIGINT, sigfun);
    (void) signal(SIGTERM, sigfun);

    inp.open("/etc/crypttab");
    if(!inp) {
       cerr << "ERROR: /etc/crypttab could not be opeend." << endl;
       return 1;
    }

    getline(inp, cryptstring);
    while ((!inp.eof())) {
       if (cryptstring[0] ==  '#') {
          cryptstring = "";
       }
       inp >> cryptstring;
    }
    inp.close();

    string cryptstring_sub;
    if(cryptstring.empty())  {
      cout << "ERROR: This host currently is not using encryption." << endl;
      cout << "This program should only be run on machines with drive encryption enabled." << endl;
      return 1;

    } else {
       cryptpart = cryptstring.substr(0, cryptstring.find("_"));
       cryptpart = "/dev/" + cryptpart;
    }
    termios oldt;
    tcgetattr(STDIN_FILENO, &oldt);
    termios newt = oldt;
    newt.c_lflag &= ~ECHO;
    tcsetattr(STDIN_FILENO, TCSANOW, &newt);

   // Try to open the cryptainer with the default password to set the admin passwords.
   closeCrypt(defchk);
   sprintf(cmd, "echo '%s' | cryptsetup luksOpen --readonly %s %s >/dev/null 2>&1", defpw, cryptpart.c_str(), defchk.c_str());
   exitStatus = system(cmd);
   exitStatus = WEXITSTATUS(exitStatus);
   closeCrypt(defchk);
   if (exitStatus == 0) {
#ifdef DEBUG
      cout << "Setting admin passwords for the 1st time." << endl;
#endif
      sprintf(cmd, "cryptsetup luksAddKey -S 5 %s", cryptpart.c_str());
      encryptAdd(cmd, defpw, dfspw);
      sprintf(cmd, "cryptsetup luksAddKey -S 6 %s", cryptpart.c_str());
      encryptAdd(cmd, defpw, engpw);
      sprintf(cmd, "cryptsetup luksAddKey -S 7 %s", cryptpart.c_str());
      encryptAdd(cmd, defpw, secpw);
   } else {
#ifdef DEBUG
      cout << "Changing admin passwords." << endl;
#endif
      // Try to unlock each slot with the accompanying password, if it doesn't work,
      // then it needs to be changed.
      // First find a known good password.  1 of the 3 should work.
      closeCrypt(defchk);
      sprintf(cmd, "echo '%s' | cryptsetup luksOpen --readonly %s %s >/dev/null 2>&1", dfspw, cryptpart.c_str(), defchk.c_str());
      exitStatus = system(cmd);
      exitStatus = WEXITSTATUS(exitStatus);
      closeCrypt(defchk);
      if (exitStatus == 0) {
         strcpy(usepw, dfspw);
#ifdef DEBUG
         cout << "using DFS Pass.\n" << endl;
#endif
      } else {
         changeDfs = 1;
#ifdef DEBUG
         cout << "DFS pass needs to be changed.\n" << endl;
#endif
      }

      sprintf(cmd, "echo '%s' | cryptsetup luksOpen --readonly %s %s >/dev/null 2>&1", engpw, cryptpart.c_str(), defchk.c_str());
      exitStatus = system(cmd);
      exitStatus = WEXITSTATUS(exitStatus);
      closeCrypt(defchk);
      if (exitStatus == 0) {
         if ( usepw[0] == '\0' ) {
            strcpy(usepw, engpw);
#ifdef DEBUG
            cout << "using ENG Pass.\n" << endl;
#endif
         }
      } else {
         changeEng = 1;
#ifdef DEBUG
         cout << "ENG pass needs to be changed.\n" << endl;
#endif
      }

      sprintf(cmd, "echo '%s' | cryptsetup luksOpen --readonly %s %s >/dev/null 2>&1", secpw, cryptpart.c_str(), defchk.c_str());
      exitStatus = system(cmd);
      exitStatus = WEXITSTATUS(exitStatus);
      closeCrypt(defchk);
      if (exitStatus == 0) {
         if ( usepw[0] == '\0' ) {
            strcpy(usepw, secpw);
#ifdef DEBUG
            cout << "using Sec Pass.\n" << endl;
#endif
         }
      } else {
         changeSec = 1;
#ifdef DEBUG
         cout << "Security pass needs to be changed.\n" << endl;
#endif
      }

      if (changeDfs == 1 ) {
         sprintf(cmd, "cryptsetup luksKillSlot %s 5", cryptpart.c_str());
         encryptKill(cmd, usepw);
         sprintf(cmd, "cryptsetup luksAddKey -S 5 %s", cryptpart.c_str());
         encryptAdd(cmd, usepw, dfspw);
      }

      if (changeEng == 1 ) {
         sprintf(cmd, "cryptsetup luksKillSlot %s 6", cryptpart.c_str());
         encryptKill(cmd, usepw);
         sprintf(cmd, "cryptsetup luksAddKey -S 6 %s", cryptpart.c_str());
         encryptAdd(cmd, usepw, engpw);
      }

      if (changeSec == 1 ) {
         sprintf(cmd, "cryptsetup luksKillSlot %s 7", cryptpart.c_str());
         encryptKill(cmd, usepw);
         sprintf(cmd, "cryptsetup luksAddKey -S 7 %s", cryptpart.c_str());
         encryptAdd(cmd, usepw, secpw);
      }

   }

   tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
   return 0;
}
