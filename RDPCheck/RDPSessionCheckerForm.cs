//A program that checks for active Remote Desktop Protocol sessions and if active outputs name of individual who currently has session
//Liam Harper

using System;
using System.Net;
using System.Windows.Forms;
using Microsoft.Win32;
using System.DirectoryServices.AccountManagement;
using System.Drawing;
using System.Threading.Tasks;
using ImpersonateWindowsUser_NS;
using impersonateQWINSTA;


namespace RDPCheck
{

    public partial class frmRDPSessionChecker : Form
    {

        //Retrieve server name to check from listbox
        public string serverToCheck;
        public string clientName;
        public frmRDPSessionChecker()
        {
            InitializeComponent();

        }

        private void btnRefresh_Click(object sender, EventArgs e)
        {
            //Sets all buttons to gray before they are given colours
            for (int i = 1; i < 10; i = i + 1)
            {
                this.Controls[i].BackColor = Color.Gray;
                this.Controls[i].Refresh();
            }

            //Launches form before load events are complete
            this.Show();
            this.Refresh();

                Parallel.Invoke(

            //Used as dud (first invoke is always the first in this list so one button becomes gray long before the others if this is not implemented)
            () => RDPCheck(10, 0),
            //
            () => RDPCheck(1, 0),
            () => RDPCheck(2, 1),
            () => RDPCheck(3, 2),
            () => RDPCheck(4, 3),
            () => RDPCheck(5, 4),
            () => RDPCheck(6, 5),
            () => RDPCheck(7, 6),
            () => RDPCheck(8, 7),
            () => RDPCheck(9, 8)

            );

      
        }

        public void RDPCheck(int controlNumberToUse, int listBoxIndexNumber)
        {
            try
            {
                //Retrieve IP Address from above server name
                string serverToCheck;
                serverToCheck = lstServers.GetItemText(lstServers.Items[listBoxIndexNumber]).Substring(0, 12);
                IPAddress[] ipToCheck = Dns.GetHostAddresses(serverToCheck);

                //Specify cmd command string
                string isSessionActiveOutput = "";

                //Launch CMD instance (argument of QWINSTA is contained in class)
                isSessionActiveOutput = ProcessImpersonator.ImpersonateProcess_WithProfile(@"C:\Windows\System32\cmd.exe", "aberdeen", "svcobieeadmin", "passwordGoesHere", ipToCheck[0]);

                //If output contains rdpwd then a rdp session is active
                if (isSessionActiveOutput.Contains("rdpwd"))
                {

                    //Impersonate SVCOBIEEADMIN account in order to access registries of servers running on via SVCOBIEEADMIN user
                    using (ImpersonateWindowsUserClass.Impersonator impersonator = new ImpersonateWindowsUserClass.Impersonator())
                    {
                        PrincipalContext principalContext = new PrincipalContext(ContextType.Domain);
                        UserPrincipal userName = UserPrincipal.FindByIdentity(principalContext, "svcobieeadmin");
                        //SID of RDP session is used as HKEY_USERS cannot be accessed via remote registry when using a username
                        var userSID = userName.Sid;

                        //Retrieve clientName (name of computer connected via RDP) key from HKEY_USERS\*SID*\Volatile Environment\2
                        RegistryKey environmentKey = RegistryKey.OpenRemoteBaseKey(RegistryHive.Users, Convert.ToString(ipToCheck[0]));
                        RegistryKey volatileEnvironmentFolder = environmentKey.OpenSubKey(userSID + @"\Volatile Environment\2", false);
                        clientName = (string)volatileEnvironmentFolder.GetValue("CLIENTNAME");
                    }

                    string user = "";

                    if (clientName == "exampleComputerName")
                    {
                        user = "exampleUser";
                    }
                    else
                    {
                        user = "Unknown (" + clientName + ")";
                    }  

                    Button.CheckForIllegalCrossThreadCalls = false;
                    this.Controls[10 - controlNumberToUse].BackColor = Color.Green;
                    this.Controls[10 - controlNumberToUse].ForeColor = Color.Green;
                    this.Controls[10 - controlNumberToUse].Text = user;
                }

                else
                {
                    this.Controls[10 - controlNumberToUse].BackColor = Color.Red;

                    Button.CheckForIllegalCrossThreadCalls = false;
                    this.Controls[10 - controlNumberToUse].Text = "button";
                }

            }
            catch (Exception exception)
            {
                Button.CheckForIllegalCrossThreadCalls = false;
                this.Controls[10 - controlNumberToUse].BackColor = Color.Gray;
                this.Controls[10 - controlNumberToUse].Text = Convert.ToString(exception);
            }

        }


        private void frmRDPSessionChecker_Load(object sender, EventArgs e)
        {
            //Assigns button click events in one line instead of 10 +
            for (int i = 2; i < 11; i++)
            {
                this.Controls["button" + Convert.ToString(i)].Click += buttonClicked;
            }

            //Performs click of Refresh button on startup to initially load buttons
            btnRefresh.PerformClick();           
        }

        private void buttonClicked(object sender, EventArgs e)

        {
            Button button = (Button)sender;

            if (button.Text.Contains("button"))
            {
                MessageBox.Show("Not in use.");
            }
            //If button text length is over 20 contents should contain error
            else if(button.Text.Length > 20)
            {
                MessageBox.Show(button.Text);
            }     
            else                     
            {
                MessageBox.Show("In use by: " + button.Text + ".");
            }

            //Focuses on invisible button
            invisibleButton.Focus();


        } 
        }

    }






