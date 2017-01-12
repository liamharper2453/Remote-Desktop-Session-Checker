using System;
using System.Windows.Forms;

namespace RDPCheck
{
    static class RDPSessionChecker
    {
        /// <summary>
        /// The main entry point for the application.
        /// </summary>
        [STAThread]
        static void Main()
        {
           Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            Application.Run(new frmRDPSessionChecker());
        }
    }
}
