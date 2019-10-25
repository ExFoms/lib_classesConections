using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Net.NetworkInformation;
using System.Security.AccessControl;
using System.Security.Principal;
using System.IO;
using System.Threading;
using System.Diagnostics;
using System.Data.SqlClient;
using System.Data;
using System.Net.Mail;
using System.Net;


public class clsPing
{
    public bool busy;           //занят ли работой
    public DateTime time;
    public bool active;         //есть пиинг
    public Thread thread;       //пинг доступа
    public bool exec_inprocess; //запуск программы находится в процессе
    public int connectionType;  //  1 - ip, 2 - folders, 3 - email VipNet, 4 - program
    public object ping_resource;
    public clsPing()
    {
        busy = false;
        time = DateTime.Now;
        exec_inprocess = false;
    }
    public void ping()
    {
        if (busy == true && time.AddSeconds(5) > DateTime.Now) //пинг завис
        {
            thread.Abort();
            thread.Join();
            busy = false;
            active = false;
        }
        if (busy != true)
        {
            thread = new Thread(threadPing) { IsBackground = true };
            busy = true;
            time = DateTime.Now;
            thread.Start();
            busy = false;
        }
    }
    private void threadPing()
    {
        switch (connectionType)
        {
            case 1: active = ping_ip(); break;
            case 2: active = ping_folders(); break;
            case 3: active = ping_folders(); break;
            case 4: active = ping_program(); break;
        }
    }
    private bool ping_ip()
    {
        try
        {
            Ping ping = new System.Net.NetworkInformation.Ping();
            PingReply pingReply = null;
            pingReply = ping.Send((string)ping_resource);
            ping.Dispose();
            return (pingReply.Status == IPStatus.Success);

        }
        catch
        {
            return false;
        }
    }
    private bool ping_folders()
    {
        var isInRoleWithAccess = false;
        FileSystemRights accessRights = FileSystemRights.FullControl; ;
        foreach (string path in (string[])ping_resource)
            try
            {
                var di = new DirectoryInfo(path);
                var acl = di.GetAccessControl();
                var rules = acl.GetAccessRules(true, true, typeof(NTAccount));

                var currentUser = WindowsIdentity.GetCurrent();
                var principal = new WindowsPrincipal(currentUser);
                foreach (AuthorizationRule rule in rules)
                {
                    var fsAccessRule = rule as FileSystemAccessRule;
                    if (fsAccessRule == null)
                        continue;

                    if ((fsAccessRule.FileSystemRights & accessRights) > 0)
                    {
                        var ntAccount = rule.IdentityReference as NTAccount;
                        if (ntAccount == null)
                            continue;

                        if (principal.IsInRole(ntAccount.Value))
                        {
                            if (fsAccessRule.AccessControlType == AccessControlType.Deny)
                                return false;
                            isInRoleWithAccess = true;
                        }
                    }
                }
            }
            catch
            {
                return false;
            }
        return isInRoleWithAccess;
    }
    private bool ping_program()
    {
        try
        {
            bool ping_true = (Process.GetProcessesByName(Path.GetFileNameWithoutExtension((string)ping_resource)).Length > 0);
            if (ping_true) exec_inprocess = false;
            if (!ping_true && !exec_inprocess) exec_program();
            return ping_true;
        }
        catch
        {
            return false;
        }
    }
    public void exec_program()
    {
        try
        {
            Process[] proceses = Process.GetProcessesByName(Path.GetFileNameWithoutExtension((string)ping_resource));
            if (proceses.Count() == 0 && !exec_inprocess)
            {
                exec_inprocess = true;
                Process.Start((string)ping_resource);
            }
            else
            {
                exec_inprocess = false;
            }
        }
        catch
        {
        }
    }
    public void stop_program()
    {
        Process[] proceses = Process.GetProcessesByName(Path.GetFileNameWithoutExtension((string)ping_resource));
        foreach (Process proces in proceses)
        {
            if (proces.Responding)
            {
                proces.CloseMainWindow();
                proces.WaitForExit();
            }
            else
            {
                proces.Kill();
            }
        }
    }


}


public class clsConfigPrototype
/* Определяет исходную структуру и методы 
 * 
 */
{
    public Thread thread;
    public bool busy = false;
    public string name;
    public string nameHandler;
    public int nrecord;
    public string comment, comment_dop;
    public bool active = false;          //указывает доступность контрольной точки
    public bool enable = true;         //включен ли контроль доступа
    public bool change_status = false;  //был ли изменен статус доступности контрольной точки
    public clsPing ping = new clsPing();
    public int tick;
    private Thread threadController;
    //public Metod_Log metod_log; //для передачи метода публикации лога из основного класса
    public void check()
    {
        if (enable)
        {
            ping.ping();
            change_status = (active != ping.active) ? true : false;
            active = ping.active;
        }
    }    
    public void controllerStart() //Бесконечный цикл 
    {
        threadController = new Thread(() =>
        {
            while (true)
            {
                if (enable) start();
                Thread.Sleep(TimeSpan.FromSeconds(tick));                
            }
        })
        { IsBackground = true };
        threadController.Start();
    }
    public virtual void start()
    { 
    }
}

public class clsConnections : clsConfigPrototype
/* Определяет контролируемые соединения и работающие программы
 * 
 * 
 */
{

    public string connectionString;
    public int restartInterval;

    public void startRestart()
    {
        Thread threadRestart_;
        threadRestart_ = new Thread(controler);
        threadRestart_.IsBackground = true;
        threadRestart_.Start();
    }
    public void controler() //Бесконечный цикл 
    {
        while (true)
        {
            Thread.Sleep(TimeSpan.FromMinutes(restartInterval));
            ping.stop_program();
        }
    }
}

public class clsTransport_files : clsConfigPrototype
/* Определяет транспорт файлов
 * 
 * 
 */
{
    public string prefix;
    public string[] masks;
    public bool rewrite;
    public override void start()
    {
        check();
        if (busy != true && active)
        {
            thread = new Thread(transport_file) { IsBackground = true };
            thread.Start();
        }
    }
    public void transport_file()
    {
        try
        {
            var dir_source = new DirectoryInfo(((string[])ping.ping_resource)[0]);
            var dir_destination = new DirectoryInfo(((string[])ping.ping_resource)[1]);
            DateTime now = DateTime.Now;
            string path;
            foreach (string mask in masks)
            {
                string[] sourceFiles = Directory.GetFiles(dir_source.ToString(), mask);
                foreach (string f in sourceFiles)
                {
                    busy = true;
                    comment_dop = "Перемещаю файл: " + Path.GetFileName(f) + " в папку: " + @dir_destination.ToString() + ((string.IsNullOrEmpty(prefix)) ? string.Empty : "префикс - " + prefix);
                    path = Path.Combine(@dir_destination.ToString(), String.Format("{0}{1}", ((string.IsNullOrEmpty(prefix)) ? string.Empty : prefix),Path.GetFileName(f)));
                    try
                    {
                        if (rewrite && File.Exists(path)) File.Delete(path);
                        File.Move(f, path);
                        /*metod_log(new clsLog(
                            DateTime.Now,
                            9,
                            Path.GetFileName(f),
                            0,
                            6,
                            now,
                            now,
                            String.Format("перемещен: {0}", path)
                            ));*/
                    }
                    catch
                    {
                        //comment_dop = "Ошибка";//return false; Игнорируем случаи проблемы переноса файла, чаще всего возникает тк уже имеется на том конце файл
                    }
                    comment_dop = "";
                    busy = false;
                }
            }
        }
        catch { }
    }
}

public class clsTransport_files_inpersonalfolder : clsConfigPrototype
/* Определяет адресный транспорт файлов
 * 
 * 
 */
{
    public string[] recipients; // {type,recipient} в свойствах
    public bool rewrite;
    public string prefix;
    public string[] masks; // в свойствах есть comment;
    public override void start()
    {
        check();
        if (busy != true && active)
        {
            thread = new Thread(transport_file) { IsBackground = true };
            thread.Start();
        }
    }
    public void transport_file()
    {
        try
        {
            var dir_source = new DirectoryInfo(((string[])ping.ping_resource)[0]);
            var dir_destination = new DirectoryInfo(((string[])ping.ping_resource)[1]);
            DateTime now = DateTime.Now;
            string path;
            foreach (string mask in masks)
            {
                foreach (string recipient in recipients)
                {
                    string[] inputList = Directory.GetFiles(dir_source.ToString(), mask.Replace("#", recipient));
                    foreach (string f in inputList)
                    {
                        busy = true;
                        //comment_dop = "Перемещаю файл: " + Path.GetFileName(f) + " в папку: " + @dir_destination.ToString();
                        //path = Path.Combine(@dir_destination.ToString(), recipient, Path.GetFileName(f));
                        comment_dop = "Перемещаю файл: " + Path.GetFileName(f) + " в папку: " + @dir_destination.ToString() + ((string.IsNullOrEmpty(prefix)) ? string.Empty : "префикс - " + prefix);
                        path = Path.Combine(@dir_destination.ToString(), recipient, String.Format("{0}{1}", ((string.IsNullOrEmpty(prefix)) ? string.Empty : prefix), Path.GetFileName(f)));
                        try
                        {
                            if (rewrite && File.Exists(path)) File.Delete(path);
                            File.Move(f, path);
                            /*metod_log(new clsLog(
                                DateTime.Now, // дата лога
                                9,  //важность
                                Path.GetFileName(f), //Имя
                                0,  //область ТФОМС
                                6,  //тип задачи
                                now,    //время старта операции
                                now,    //время окончания операции
                                String.Format("перемещен: {0}", path) //комментарии
                                ));*/
                        }
                        catch
                        {
                            //return false; Игнорируем случаи проблемы переноса файла, чаще всего возникает тк уже имеется на том конце файл
                        }
                        comment_dop = "";
                        busy = false;
                    }
                }
            }
        }
        catch { }
    }

}

public class clstransport_files_email : clsConfigPrototype
/* Определяет транспорт электронной почтой
 * 
 * 
 */
{
    public string folder;
    public string email;
    public string caption;
    public override void start()
    {
        check();
        if (busy != true && active)
        {
            thread = new Thread(transport_file) { IsBackground = true };
            thread.Start();
        }

    }
    public void transport_file()
    {
        DateTime now = DateTime.Now;
        string mask = "*";
        try
        {
            string[] inputList = Directory.GetFiles(folder, mask);
            foreach (string f in inputList)
            {
                try
                {
                    busy = true;
                    comment_dop = "Отправляю почту на адрес: " + email;
                    if (SendMail(
                            "192.168.1.2",
                            "AOFOMS Gateware server-shrk@aofoms.tsl.ru",
                            "A3z4y5",
                            email,
                            caption,
                            "Сообщение автопроцесс",
                            f))
                    {
                        File.Delete(f);
                        /*metod_log(new clsLog(
                            DateTime.Now,
                            9,
                            Path.GetFileName(f),
                            0,
                            6,
                            now,
                            now,
                            String.Format("отправлен почтой: {0}", email)
                            ));*/
                    }
                }
                catch
                {
                }
                comment_dop = "";
                busy = false;
            }
        }
        catch { }
    }

    //Сопутствующие методы

    public static bool SendMail(string smtpServer, string from, string password, string mailto, string caption, string message, string attachFile = null)
    {
        try
        {
            MailMessage mail = new MailMessage();
            mail.From = new MailAddress(from);
            mail.To.Add(new MailAddress(mailto));
            mail.Subject = caption;
            mail.Body = message;
            if (!string.IsNullOrEmpty(attachFile))
                mail.Attachments.Add(new Attachment(attachFile));
            SmtpClient client = new SmtpClient();
            client.Host = smtpServer;
            client.Port = 5025;
            client.EnableSsl = false;
            client.Credentials = new NetworkCredential(from.Split('@')[0], password);
            client.DeliveryMethod = SmtpDeliveryMethod.Network;
            client.Send(mail);
            mail.Dispose();
            return true;
        }
        catch
        {
            return false;
        }
    }
}
