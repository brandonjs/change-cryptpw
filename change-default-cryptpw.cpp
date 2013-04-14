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
    int exitStatus;
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
            printf("Got %d.  That should be a prompt.\n", result);
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
            printf("Got %d.  That should be a prompt.\n", result);
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
    char cmd[128], defpw[] = { 'q', 'u', 'a', 'l', 'c', 'o', 'm', 'm', '1', '\0' };
    string itSlot, pwSlot, defchk = "pwchk", itchk = "itpwchk", plymFile, cryptkey, cryptkey2, oldkey, cryptstring, cryptpart;
    int pwslot = 0, itslot = 0, newslot = 4, exitStatus = 255;
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

   // Try to open the cryptainer with the default password.
   // If it succeeds then the user needs to change the password.
   closeCrypt(defchk);
   sprintf(cmd, "echo '%s' | cryptsetup luksOpen --readonly %s %s 2>&1 | awk '{print $3}' | egrep -v '[5-7]'", defpw, cryptpart.c_str(), defchk.c_str());
   pwSlot = exec(cmd);
   if (pwSlot.empty()) {
         pwSlot[0] = '0';
   }

   if (isdigit(pwSlot[0])) {
      pwslot = pwSlot[0] - '0';
      if (pwslot == newslot) {
         pwslot = 3;
      }
      closeCrypt(defchk);
      exitStatus = system("plymouth --ping");
      exitStatus = WEXITSTATUS(exitStatus);
      if((access("/bin/plymouth",X_OK) == 0) && (exitStatus == 1)) { 
         cout << "You must change your drive encryption password." << endl;
         cout << "Preferably this should match your QualPass." << endl;
         cout << "Enter new passphrase: ";
         getline(cin, cryptkey);
         cout << endl;
         closeCrypt(itchk);
         sprintf(cmd, "echo '%s' | cryptsetup luksOpen --readonly %s %s 2>&1 | awk '{print $3}'", cryptkey.c_str(), cryptpart.c_str(), itchk.c_str());
         itSlot = exec(cmd);
         if (isdigit(itSlot[0])) {
            itslot = itSlot[0] - '0';
         }
         if ((itslot == 5) || (itslot == 6) || (itslot == 7)) {
            cout << "IT Password accepted, exiting script and booting to OS." << endl;
            sleep(1);                                                                 
            closeCrypt(itchk);
            tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
            return 1;
         }
         cout << "Enter passphrase again: ";
         getline(cin, cryptkey2);
         cout << endl;
         while ((cryptkey.empty()) || (cryptkey == defpw) || (cryptkey != cryptkey2)) {
            if (cryptkey.empty()) {
               cout << "ERROR: Blank password not allowed." << endl;
            } else if (cryptkey == defpw ) {
               cout << "ERROR: You cannot use the same password as the default." << endl;
            } else {
               cout << "ERROR: Passwords don't match. Please re-enter your password." << endl;
            }
            cout << "Enter new passphrase: ";
            getline(cin, cryptkey);
            cout << endl;
            closeCrypt(itchk);
            sprintf(cmd, "echo '%s' | cryptsetup luksOpen --readonly %s %s 2>&1 | awk '{print $3}'", cryptkey.c_str(), cryptpart.c_str(), itchk.c_str());
            itSlot = exec(cmd);
            if (isdigit(itSlot[0])) {
               itslot = itSlot[0] - '0';
            }
            if ((itslot == 5) || (itslot == 6) || (itslot == 7)) {
               cout << "IT Password accepted, exiting script and booting to OS." << endl;
               closeCrypt(itchk);
               sleep(1);                                                                 
               tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
               return 1;
            }
            cout << "Enter passphrase again: ";
            getline(cin, cryptkey2);
            cout << endl;
         }
         cout << "New password accepted, setting now." << endl;
      } else {
         // plymouth is running... 
         sprintf(cmd, "plymouth message --text='Your drive encryption password needs to be changed from the default.'");
         exec(cmd);
         sprintf(cmd, "plymouth --wait ask-for-password --prompt='Enter new passphrase:'");
         cryptkey = exec(cmd);
         closeCrypt(itchk);
         sprintf(cmd, "echo '%s' | cryptsetup luksOpen --readonly %s %s 2>&1 | awk '{print $3}'", cryptkey.c_str(), cryptpart.c_str(), itchk.c_str());
         itSlot = exec(cmd);
         if (isdigit(itSlot[0])) {
            itslot = itSlot[0] - '0';
         }
         if ((itslot == 5) || (itslot == 6) || (itslot == 7)) {
            sprintf(cmd, "plymouth message --text='IT Password accepted, exiting script and booting to OS.'");
            exec(cmd);
            sleep(1);                                                                 
            closeCrypt(itchk);
            tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
            return 1;
         }
         sprintf(cmd, "plymouth --wait ask-for-password --prompt='Enter passphrase again:'");
         cryptkey2=exec(cmd);
         while ((cryptkey.empty()) || (cryptkey == defpw) || (cryptkey != cryptkey2)) {
            if (cryptkey.empty()) {
               sprintf(cmd, "plymouth message --text='ERROR: Blank password not allowed.'");
               exec(cmd);
            } else if (cryptkey == defpw ) {
               sprintf(cmd, "plymouth message --text='ERROR: You cannot use the same password as the default.'");
               exec(cmd);
            } else {
               sprintf(cmd, "plymouth message --text='ERROR: Passwords don't match. Please re-enter your password.'");
               exec(cmd);
            }
            sprintf(cmd, "plymouth --wait ask-for-password --prompt='Enter new passphrase:'");
            cryptkey = exec(cmd);
            closeCrypt(itchk);
            sprintf(cmd, "echo '%s' | cryptsetup luksOpen --readonly %s %s 2>&1 | awk '{print $3}'", cryptkey.c_str(), cryptpart.c_str(), itchk.c_str());
            itSlot = exec(cmd);
            if (isdigit(itSlot[0])) {
               itslot = itSlot[0] - '0';
            }
            if ((itslot == 5) || (itslot == 6) || (itslot == 7)) {
               sprintf(cmd, "plymouth message --text='IT Password accepted, exiting script and booting to OS.'");
               exec(cmd);
               closeCrypt(itchk);
               sleep(1);                                                                 
               tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
               return 1;
            }
            sprintf(cmd, "plymouth --wait ask-for-password --prompt='Enter passphrase again:'");
            cryptkey2=exec(cmd);
         }
      sprintf(cmd, "plymouth message --text='New password accepted, setting now.'");
      exec(cmd);
      }
      sprintf(cmd, "cryptsetup luksAddKey -S %d %s", newslot, cryptpart.c_str());
      encryptAdd(cmd, defpw, cryptkey);
      sprintf(cmd, "cryptsetup luksKillSlot %s %d", cryptpart.c_str(), pwslot);
      encryptKill(cmd, cryptkey);
      sprintf(cmd, "cryptsetup luksAddKey -S %d %s", pwslot, cryptpart.c_str());
      encryptAdd(cmd, cryptkey, cryptkey);
      sprintf(cmd, "cryptsetup luksKillSlot %s %d", cryptpart.c_str(), newslot);
      encryptKill(cmd, cryptkey);
   }
   tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
   return 0;
}
