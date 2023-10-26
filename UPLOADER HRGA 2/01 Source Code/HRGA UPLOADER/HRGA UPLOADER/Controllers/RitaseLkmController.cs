using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Mvc;
using System.IO;
using HRGA_UPLOADER.Models;
using System.Data;
using System.Text.RegularExpressions;
using System.Configuration;
using System.Data.SqlClient;
using System.Threading.Tasks;
using Kendo.DynamicLinq;
using System.Net;


namespace HRGA_UPLOADER.Controllers
{
    public class RitaseLkmController : Controller
    {
        DC_HRGAONLINEDataContext i_ctx_db; 
        private string[] strArray;
        // GET: RitaseLkm
        public ActionResult Index()
        {
            return View();
        }

        [HttpPost]
        public JsonResult AjaxRead(string s_str_sesionID, int take, int skip, IEnumerable<Kendo.DynamicLinq.Sort> sort, Kendo.DynamicLinq.Filter filter)

        {
            try
            {
                i_ctx_db = new DC_HRGAONLINEDataContext();
                var tbl_temp_ritase_lkm = i_ctx_db.TBL_TEMP_RITASE_LKMs.Where(f => f.SESSION_ID == s_str_sesionID && f.STATUS == "0");
                return Json(tbl_temp_ritase_lkm.ToDataSourceResult(take, skip, sort, filter));

            }
            catch (Exception e)
            {
                return this.Json(new { error = e.ToString() }, JsonRequestBehavior.AllowGet);
            }
        }


        [HttpPost]
        public async Task<JsonResult> UploadRitaseLkm(string id)
        {
            //pv_CustLoadSession();
            DC_HRGAONLINEDataContext i_ctx_db = new DC_HRGAONLINEDataContext();
            DataTable dt = new DataTable();
            var iStrRemark = string.Empty;
            var iStrError = string.Empty;
            int i_int_countBerhasil = 0;
            int i_int_countGagal = 0;
            try
            {
               
                foreach (string file in Request.Files)
                {
                    var fileContent = Request.Files[file];

                    if (fileContent != null && fileContent.ContentLength > 0)
                    {   
                        var fileName = DateTime.Now.ToBinary().ToString() + Path.GetFileName(file);
                        var path = Path.Combine(Server.MapPath("~/FileUpload"), fileName + ".csv");
                        fileContent.SaveAs(path);
                        dt = ProcessCSV(path, id);

                        if (this.strArray.Length != 9)
                        {
                            throw new System.ArgumentException("Template CSV Tidak Valid, Pastikan Template Yang Dimasukan Template User");
                        }
                        else
                        {
                            iStrRemark = ProcessBulkCopy(dt);
                            i_ctx_db.SP_UPLOAD_RITASE_LKM(id);

                            i_int_countBerhasil = i_ctx_db.TBL_TEMP_RITASE_LKMs.Where(f => f.STATUS == "1" && f.SESSION_ID == id).Count();
                            i_int_countGagal = i_ctx_db.TBL_TEMP_RITASE_LKMs.Where(f => f.STATUS == "0" && f.SESSION_ID == id).Count();

                            i_ctx_db.Dispose();
                        }
                    }

                }
            }
            catch (Exception e)
            {
                string str_error = "Terjadi Kesalahan " + e.Message;
                Response.StatusCode = (int)HttpStatusCode.BadRequest;
                return Json(str_error);
            }

            return Json(new { remark = iStrRemark, countBerhasil = i_int_countBerhasil, countGagal = i_int_countGagal });
        }
       
        private DataTable ProcessCSV(string fileName, string sSessUpload)
        {
            //Set up our variables
            string Feedback = string.Empty;
            string line = string.Empty;
            //  string[] strArray;
            List<string> strList;

            DataTable dt = new DataTable();
            DataRow row;
            // work out where we should split on comma, but not in a sentence
            Regex r = new Regex(",(?=(?:[^\"]*\"[^\"]*\")*(?![^\"]*\"))");
            //Set the filename in to our stream
            StreamReader sr = new StreamReader(fileName);

            //Read the first line and split the string at , with our regular expression in to an array
            line = sr.ReadLine();
            strList = r.Split(line).ToList();
            strList.Insert(0, "pid");
            strList.Insert(1, "sessionID");
            strList.Add("add1");
            strList.Add("add1");
            //strArray = r.Split(line);
            this.strArray = strList.ToArray();

            //For each item in the new split array, dynamically builds our Data columns. Save us having to worry about it.
            Array.ForEach(this.strArray, s => dt.Columns.Add(new DataColumn()));

            //Read each line in the CVS file until it’s empty
            while ((line = sr.ReadLine()) != null)
            {
                row = dt.NewRow();

                //add our current value to our data row
                line = string.Format(",{0},{1},,", sSessUpload, line);
                row.ItemArray = r.Split(line);
                dt.Rows.Add(row);
            }

            //Tidy Streameader up
            sr.Dispose();

            //return a the new DataTable
            return dt;
        }

        private static String ProcessBulkCopy(DataTable dt)
        {
            string Feedback = string.Empty;
            string connString = ConfigurationManager.ConnectionStrings["DATA_ABS1ConnectionString"].ConnectionString;

            //make our connection and dispose at the end
            using (SqlConnection conn = new SqlConnection(connString))
            {
                //make our command and dispose at the end
                using (var copy = new SqlBulkCopy(conn))
                {
                    //Open our connection
                    conn.Open();
                    ///Set target table and tell the number of rows
                    copy.DestinationTableName = "UPLOADER.TBL_TEMP_RITASE_LKM";
                    copy.BatchSize = dt.Rows.Count;
                    try
                    {
                        //Send it to the server
                        copy.WriteToServer(dt);
                        Feedback = "Upload complete";
                    }
                    catch (Exception ex)
                    {
                        Feedback = ex.Message;
                    }
                }
            }
            return Feedback;
        }

    }
}