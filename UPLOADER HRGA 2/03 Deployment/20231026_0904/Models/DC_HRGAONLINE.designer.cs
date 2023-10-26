﻿#pragma warning disable 1591
//------------------------------------------------------------------------------
// <auto-generated>
//     This code was generated by a tool.
//     Runtime Version:4.0.30319.42000
//
//     Changes to this file may cause incorrect behavior and will be lost if
//     the code is regenerated.
// </auto-generated>
//------------------------------------------------------------------------------

namespace HRGA_UPLOADER.Models
{
	using System.Data.Linq;
	using System.Data.Linq.Mapping;
	using System.Data;
	using System.Collections.Generic;
	using System.Reflection;
	using System.Linq;
	using System.Linq.Expressions;
	using System.ComponentModel;
	using System;
	
	
	[global::System.Data.Linq.Mapping.DatabaseAttribute(Name="DATA_ABS1")]
	public partial class DC_HRGAONLINEDataContext : System.Data.Linq.DataContext
	{
		
		private static System.Data.Linq.Mapping.MappingSource mappingSource = new AttributeMappingSource();
		
    #region Extensibility Method Definitions
    partial void OnCreated();
    partial void InsertTBL_TEMP_UPLOAD_ROSTER(TBL_TEMP_UPLOAD_ROSTER instance);
    partial void UpdateTBL_TEMP_UPLOAD_ROSTER(TBL_TEMP_UPLOAD_ROSTER instance);
    partial void DeleteTBL_TEMP_UPLOAD_ROSTER(TBL_TEMP_UPLOAD_ROSTER instance);
    partial void InsertTBL_TEMP_REVISI_ABSEN(TBL_TEMP_REVISI_ABSEN instance);
    partial void UpdateTBL_TEMP_REVISI_ABSEN(TBL_TEMP_REVISI_ABSEN instance);
    partial void DeleteTBL_TEMP_REVISI_ABSEN(TBL_TEMP_REVISI_ABSEN instance);
    partial void InsertTBL_TEMP_SKL(TBL_TEMP_SKL instance);
    partial void UpdateTBL_TEMP_SKL(TBL_TEMP_SKL instance);
    partial void DeleteTBL_TEMP_SKL(TBL_TEMP_SKL instance);
    partial void InsertTBL_R_USER(TBL_R_USER instance);
    partial void UpdateTBL_R_USER(TBL_R_USER instance);
    partial void DeleteTBL_R_USER(TBL_R_USER instance);
    partial void InsertTBL_TEMP_ELI(TBL_TEMP_ELI instance);
    partial void UpdateTBL_TEMP_ELI(TBL_TEMP_ELI instance);
    partial void DeleteTBL_TEMP_ELI(TBL_TEMP_ELI instance);
    partial void InsertTBL_TEMP_RITASE_LKM(TBL_TEMP_RITASE_LKM instance);
    partial void UpdateTBL_TEMP_RITASE_LKM(TBL_TEMP_RITASE_LKM instance);
    partial void DeleteTBL_TEMP_RITASE_LKM(TBL_TEMP_RITASE_LKM instance);
    #endregion
		
		public DC_HRGAONLINEDataContext() : 
				base(global::System.Configuration.ConfigurationManager.ConnectionStrings["DATA_ABS1ConnectionString"].ConnectionString, mappingSource)
		{
			OnCreated();
		}
		
		public DC_HRGAONLINEDataContext(string connection) : 
				base(connection, mappingSource)
		{
			OnCreated();
		}
		
		public DC_HRGAONLINEDataContext(System.Data.IDbConnection connection) : 
				base(connection, mappingSource)
		{
			OnCreated();
		}
		
		public DC_HRGAONLINEDataContext(string connection, System.Data.Linq.Mapping.MappingSource mappingSource) : 
				base(connection, mappingSource)
		{
			OnCreated();
		}
		
		public DC_HRGAONLINEDataContext(System.Data.IDbConnection connection, System.Data.Linq.Mapping.MappingSource mappingSource) : 
				base(connection, mappingSource)
		{
			OnCreated();
		}
		
		public System.Data.Linq.Table<TBL_TEMP_UPLOAD_ROSTER> TBL_TEMP_UPLOAD_ROSTERs
		{
			get
			{
				return this.GetTable<TBL_TEMP_UPLOAD_ROSTER>();
			}
		}
		
		public System.Data.Linq.Table<TBL_TEMP_REVISI_ABSEN> TBL_TEMP_REVISI_ABSENs
		{
			get
			{
				return this.GetTable<TBL_TEMP_REVISI_ABSEN>();
			}
		}
		
		public System.Data.Linq.Table<TBL_TEMP_SKL> TBL_TEMP_SKLs
		{
			get
			{
				return this.GetTable<TBL_TEMP_SKL>();
			}
		}
		
		public System.Data.Linq.Table<TBL_R_USER> TBL_R_USERs
		{
			get
			{
				return this.GetTable<TBL_R_USER>();
			}
		}
		
		public System.Data.Linq.Table<TBL_TEMP_ELI> TBL_TEMP_ELIs
		{
			get
			{
				return this.GetTable<TBL_TEMP_ELI>();
			}
		}
		
		public System.Data.Linq.Table<TBL_TEMP_RITASE_LKM> TBL_TEMP_RITASE_LKMs
		{
			get
			{
				return this.GetTable<TBL_TEMP_RITASE_LKM>();
			}
		}
		
		[global::System.Data.Linq.Mapping.FunctionAttribute(Name="UPLOADER.SP_UPLOAD_ROSTER")]
		public int SP_UPLOAD_ROSTER([global::System.Data.Linq.Mapping.ParameterAttribute(Name="SESSION_ID", DbType="VarChar(50)")] string sESSION_ID)
		{
			IExecuteResult result = this.ExecuteMethodCall(this, ((MethodInfo)(MethodInfo.GetCurrentMethod())), sESSION_ID);
			return ((int)(result.ReturnValue));
		}
		
		[global::System.Data.Linq.Mapping.FunctionAttribute(Name="UPLOADER.SP_UPLOAD_SKL")]
		public int SP_UPLOAD_SKL([global::System.Data.Linq.Mapping.ParameterAttribute(Name="SESSION_ID", DbType="VarChar(50)")] string sESSION_ID)
		{
			IExecuteResult result = this.ExecuteMethodCall(this, ((MethodInfo)(MethodInfo.GetCurrentMethod())), sESSION_ID);
			return ((int)(result.ReturnValue));
		}
		
		[global::System.Data.Linq.Mapping.FunctionAttribute(Name="UPLOADER.SP_UPLOAD_ELIS")]
		public int SP_UPLOAD_ELIS([global::System.Data.Linq.Mapping.ParameterAttribute(Name="SESSION_ID", DbType="VarChar(50)")] string sESSION_ID, [global::System.Data.Linq.Mapping.ParameterAttribute(Name="NRP_PIC", DbType="VarChar(40)")] string nRP_PIC)
		{
			IExecuteResult result = this.ExecuteMethodCall(this, ((MethodInfo)(MethodInfo.GetCurrentMethod())), sESSION_ID, nRP_PIC);
			return ((int)(result.ReturnValue));
		}
		
		[global::System.Data.Linq.Mapping.FunctionAttribute(Name="UPLOADER.SP_UPLOAD_REVISI_ABSEN")]
		public int SP_UPLOAD_REVISI_ABSEN([global::System.Data.Linq.Mapping.ParameterAttribute(Name="SESSION_ID", DbType="VarChar(50)")] string sESSION_ID, [global::System.Data.Linq.Mapping.ParameterAttribute(Name="UPLOADER", DbType="VarChar(30)")] string uPLOADER)
		{
			IExecuteResult result = this.ExecuteMethodCall(this, ((MethodInfo)(MethodInfo.GetCurrentMethod())), sESSION_ID, uPLOADER);
			return ((int)(result.ReturnValue));
		}
		
		[global::System.Data.Linq.Mapping.FunctionAttribute(Name="UPLOADER.SP_UPLOAD_RITASE_LKM")]
		public int SP_UPLOAD_RITASE_LKM([global::System.Data.Linq.Mapping.ParameterAttribute(Name="SESSION_ID", DbType="VarChar(50)")] string sESSION_ID)
		{
			IExecuteResult result = this.ExecuteMethodCall(this, ((MethodInfo)(MethodInfo.GetCurrentMethod())), sESSION_ID);
			return ((int)(result.ReturnValue));
		}
	}
	
	[global::System.Data.Linq.Mapping.TableAttribute(Name="UPLOADER.TBL_TEMP_UPLOAD_ROSTER")]
	public partial class TBL_TEMP_UPLOAD_ROSTER : INotifyPropertyChanging, INotifyPropertyChanged
	{
		
		private static PropertyChangingEventArgs emptyChangingEventArgs = new PropertyChangingEventArgs(String.Empty);
		
		private int _PID;
		
		private string _SESSION_ID;
		
		private string _NRP;
		
		private string _ROSTER_CODE;
		
		private string _HARI_KE7;
		
		private string _STATUS;
		
		private string _REMARK;
		
    #region Extensibility Method Definitions
    partial void OnLoaded();
    partial void OnValidate(System.Data.Linq.ChangeAction action);
    partial void OnCreated();
    partial void OnPIDChanging(int value);
    partial void OnPIDChanged();
    partial void OnSESSION_IDChanging(string value);
    partial void OnSESSION_IDChanged();
    partial void OnNRPChanging(string value);
    partial void OnNRPChanged();
    partial void OnROSTER_CODEChanging(string value);
    partial void OnROSTER_CODEChanged();
    partial void OnHARI_KE7Changing(string value);
    partial void OnHARI_KE7Changed();
    partial void OnSTATUSChanging(string value);
    partial void OnSTATUSChanged();
    partial void OnREMARKChanging(string value);
    partial void OnREMARKChanged();
    #endregion
		
		public TBL_TEMP_UPLOAD_ROSTER()
		{
			OnCreated();
		}
		
		[global::System.Data.Linq.Mapping.ColumnAttribute(Storage="_PID", AutoSync=AutoSync.OnInsert, DbType="Int NOT NULL IDENTITY", IsPrimaryKey=true, IsDbGenerated=true)]
		public int PID
		{
			get
			{
				return this._PID;
			}
			set
			{
				if ((this._PID != value))
				{
					this.OnPIDChanging(value);
					this.SendPropertyChanging();
					this._PID = value;
					this.SendPropertyChanged("PID");
					this.OnPIDChanged();
				}
			}
		}
		
		[global::System.Data.Linq.Mapping.ColumnAttribute(Storage="_SESSION_ID", DbType="VarChar(50) NOT NULL", CanBeNull=false)]
		public string SESSION_ID
		{
			get
			{
				return this._SESSION_ID;
			}
			set
			{
				if ((this._SESSION_ID != value))
				{
					this.OnSESSION_IDChanging(value);
					this.SendPropertyChanging();
					this._SESSION_ID = value;
					this.SendPropertyChanged("SESSION_ID");
					this.OnSESSION_IDChanged();
				}
			}
		}
		
		[global::System.Data.Linq.Mapping.ColumnAttribute(Storage="_NRP", DbType="VarChar(20)")]
		public string NRP
		{
			get
			{
				return this._NRP;
			}
			set
			{
				if ((this._NRP != value))
				{
					this.OnNRPChanging(value);
					this.SendPropertyChanging();
					this._NRP = value;
					this.SendPropertyChanged("NRP");
					this.OnNRPChanged();
				}
			}
		}
		
		[global::System.Data.Linq.Mapping.ColumnAttribute(Storage="_ROSTER_CODE", DbType="VarChar(10)")]
		public string ROSTER_CODE
		{
			get
			{
				return this._ROSTER_CODE;
			}
			set
			{
				if ((this._ROSTER_CODE != value))
				{
					this.OnROSTER_CODEChanging(value);
					this.SendPropertyChanging();
					this._ROSTER_CODE = value;
					this.SendPropertyChanged("ROSTER_CODE");
					this.OnROSTER_CODEChanged();
				}
			}
		}
		
		[global::System.Data.Linq.Mapping.ColumnAttribute(Storage="_HARI_KE7", DbType="VarChar(50)")]
		public string HARI_KE7
		{
			get
			{
				return this._HARI_KE7;
			}
			set
			{
				if ((this._HARI_KE7 != value))
				{
					this.OnHARI_KE7Changing(value);
					this.SendPropertyChanging();
					this._HARI_KE7 = value;
					this.SendPropertyChanged("HARI_KE7");
					this.OnHARI_KE7Changed();
				}
			}
		}
		
		[global::System.Data.Linq.Mapping.ColumnAttribute(Storage="_STATUS", DbType="VarChar(2)")]
		public string STATUS
		{
			get
			{
				return this._STATUS;
			}
			set
			{
				if ((this._STATUS != value))
				{
					this.OnSTATUSChanging(value);
					this.SendPropertyChanging();
					this._STATUS = value;
					this.SendPropertyChanged("STATUS");
					this.OnSTATUSChanged();
				}
			}
		}
		
		[global::System.Data.Linq.Mapping.ColumnAttribute(Storage="_REMARK", DbType="VarChar(MAX)")]
		public string REMARK
		{
			get
			{
				return this._REMARK;
			}
			set
			{
				if ((this._REMARK != value))
				{
					this.OnREMARKChanging(value);
					this.SendPropertyChanging();
					this._REMARK = value;
					this.SendPropertyChanged("REMARK");
					this.OnREMARKChanged();
				}
			}
		}
		
		public event PropertyChangingEventHandler PropertyChanging;
		
		public event PropertyChangedEventHandler PropertyChanged;
		
		protected virtual void SendPropertyChanging()
		{
			if ((this.PropertyChanging != null))
			{
				this.PropertyChanging(this, emptyChangingEventArgs);
			}
		}
		
		protected virtual void SendPropertyChanged(String propertyName)
		{
			if ((this.PropertyChanged != null))
			{
				this.PropertyChanged(this, new PropertyChangedEventArgs(propertyName));
			}
		}
	}
	
	[global::System.Data.Linq.Mapping.TableAttribute(Name="UPLOADER.TBL_TEMP_REVISI_ABSEN")]
	public partial class TBL_TEMP_REVISI_ABSEN : INotifyPropertyChanging, INotifyPropertyChanged
	{
		
		private static PropertyChangingEventArgs emptyChangingEventArgs = new PropertyChangingEventArgs(String.Empty);
		
		private int _PID;
		
		private string _SESSION_ID;
		
		private string _NRP;
		
		private string _TANGGAL;
		
		private string _SHIFT;
		
		private string _IN;
		
		private string _OUT;
		
		private string _ROSTER_CODE;
		
		private string _KODE_ABSEN;
		
		private string _STATUS;
		
		private string _REMARK;
		
    #region Extensibility Method Definitions
    partial void OnLoaded();
    partial void OnValidate(System.Data.Linq.ChangeAction action);
    partial void OnCreated();
    partial void OnPIDChanging(int value);
    partial void OnPIDChanged();
    partial void OnSESSION_IDChanging(string value);
    partial void OnSESSION_IDChanged();
    partial void OnNRPChanging(string value);
    partial void OnNRPChanged();
    partial void OnTANGGALChanging(string value);
    partial void OnTANGGALChanged();
    partial void OnSHIFTChanging(string value);
    partial void OnSHIFTChanged();
    partial void OnINChanging(string value);
    partial void OnINChanged();
    partial void OnOUTChanging(string value);
    partial void OnOUTChanged();
    partial void OnROSTER_CODEChanging(string value);
    partial void OnROSTER_CODEChanged();
    partial void OnKODE_ABSENChanging(string value);
    partial void OnKODE_ABSENChanged();
    partial void OnSTATUSChanging(string value);
    partial void OnSTATUSChanged();
    partial void OnREMARKChanging(string value);
    partial void OnREMARKChanged();
    #endregion
		
		public TBL_TEMP_REVISI_ABSEN()
		{
			OnCreated();
		}
		
		[global::System.Data.Linq.Mapping.ColumnAttribute(Storage="_PID", AutoSync=AutoSync.OnInsert, DbType="Int NOT NULL IDENTITY", IsPrimaryKey=true, IsDbGenerated=true)]
		public int PID
		{
			get
			{
				return this._PID;
			}
			set
			{
				if ((this._PID != value))
				{
					this.OnPIDChanging(value);
					this.SendPropertyChanging();
					this._PID = value;
					this.SendPropertyChanged("PID");
					this.OnPIDChanged();
				}
			}
		}
		
		[global::System.Data.Linq.Mapping.ColumnAttribute(Storage="_SESSION_ID", DbType="VarChar(50)")]
		public string SESSION_ID
		{
			get
			{
				return this._SESSION_ID;
			}
			set
			{
				if ((this._SESSION_ID != value))
				{
					this.OnSESSION_IDChanging(value);
					this.SendPropertyChanging();
					this._SESSION_ID = value;
					this.SendPropertyChanged("SESSION_ID");
					this.OnSESSION_IDChanged();
				}
			}
		}
		
		[global::System.Data.Linq.Mapping.ColumnAttribute(Storage="_NRP", DbType="VarChar(20)")]
		public string NRP
		{
			get
			{
				return this._NRP;
			}
			set
			{
				if ((this._NRP != value))
				{
					this.OnNRPChanging(value);
					this.SendPropertyChanging();
					this._NRP = value;
					this.SendPropertyChanged("NRP");
					this.OnNRPChanged();
				}
			}
		}
		
		[global::System.Data.Linq.Mapping.ColumnAttribute(Storage="_TANGGAL", DbType="VarChar(20)")]
		public string TANGGAL
		{
			get
			{
				return this._TANGGAL;
			}
			set
			{
				if ((this._TANGGAL != value))
				{
					this.OnTANGGALChanging(value);
					this.SendPropertyChanging();
					this._TANGGAL = value;
					this.SendPropertyChanged("TANGGAL");
					this.OnTANGGALChanged();
				}
			}
		}
		
		[global::System.Data.Linq.Mapping.ColumnAttribute(Storage="_SHIFT", DbType="VarChar(2)")]
		public string SHIFT
		{
			get
			{
				return this._SHIFT;
			}
			set
			{
				if ((this._SHIFT != value))
				{
					this.OnSHIFTChanging(value);
					this.SendPropertyChanging();
					this._SHIFT = value;
					this.SendPropertyChanged("SHIFT");
					this.OnSHIFTChanged();
				}
			}
		}
		
		[global::System.Data.Linq.Mapping.ColumnAttribute(Name="[IN]", Storage="_IN", DbType="VarChar(10)")]
		public string IN
		{
			get
			{
				return this._IN;
			}
			set
			{
				if ((this._IN != value))
				{
					this.OnINChanging(value);
					this.SendPropertyChanging();
					this._IN = value;
					this.SendPropertyChanged("IN");
					this.OnINChanged();
				}
			}
		}
		
		[global::System.Data.Linq.Mapping.ColumnAttribute(Storage="_OUT", DbType="VarChar(10)")]
		public string OUT
		{
			get
			{
				return this._OUT;
			}
			set
			{
				if ((this._OUT != value))
				{
					this.OnOUTChanging(value);
					this.SendPropertyChanging();
					this._OUT = value;
					this.SendPropertyChanged("OUT");
					this.OnOUTChanged();
				}
			}
		}
		
		[global::System.Data.Linq.Mapping.ColumnAttribute(Storage="_ROSTER_CODE", DbType="VarChar(3)")]
		public string ROSTER_CODE
		{
			get
			{
				return this._ROSTER_CODE;
			}
			set
			{
				if ((this._ROSTER_CODE != value))
				{
					this.OnROSTER_CODEChanging(value);
					this.SendPropertyChanging();
					this._ROSTER_CODE = value;
					this.SendPropertyChanged("ROSTER_CODE");
					this.OnROSTER_CODEChanged();
				}
			}
		}
		
		[global::System.Data.Linq.Mapping.ColumnAttribute(Storage="_KODE_ABSEN", DbType="VarChar(4)")]
		public string KODE_ABSEN
		{
			get
			{
				return this._KODE_ABSEN;
			}
			set
			{
				if ((this._KODE_ABSEN != value))
				{
					this.OnKODE_ABSENChanging(value);
					this.SendPropertyChanging();
					this._KODE_ABSEN = value;
					this.SendPropertyChanged("KODE_ABSEN");
					this.OnKODE_ABSENChanged();
				}
			}
		}
		
		[global::System.Data.Linq.Mapping.ColumnAttribute(Storage="_STATUS", DbType="VarChar(2)")]
		public string STATUS
		{
			get
			{
				return this._STATUS;
			}
			set
			{
				if ((this._STATUS != value))
				{
					this.OnSTATUSChanging(value);
					this.SendPropertyChanging();
					this._STATUS = value;
					this.SendPropertyChanged("STATUS");
					this.OnSTATUSChanged();
				}
			}
		}
		
		[global::System.Data.Linq.Mapping.ColumnAttribute(Storage="_REMARK", DbType="VarChar(MAX)")]
		public string REMARK
		{
			get
			{
				return this._REMARK;
			}
			set
			{
				if ((this._REMARK != value))
				{
					this.OnREMARKChanging(value);
					this.SendPropertyChanging();
					this._REMARK = value;
					this.SendPropertyChanged("REMARK");
					this.OnREMARKChanged();
				}
			}
		}
		
		public event PropertyChangingEventHandler PropertyChanging;
		
		public event PropertyChangedEventHandler PropertyChanged;
		
		protected virtual void SendPropertyChanging()
		{
			if ((this.PropertyChanging != null))
			{
				this.PropertyChanging(this, emptyChangingEventArgs);
			}
		}
		
		protected virtual void SendPropertyChanged(String propertyName)
		{
			if ((this.PropertyChanged != null))
			{
				this.PropertyChanged(this, new PropertyChangedEventArgs(propertyName));
			}
		}
	}
	
	[global::System.Data.Linq.Mapping.TableAttribute(Name="UPLOADER.TBL_TEMP_SKL")]
	public partial class TBL_TEMP_SKL : INotifyPropertyChanging, INotifyPropertyChanged
	{
		
		private static PropertyChangingEventArgs emptyChangingEventArgs = new PropertyChangingEventArgs(String.Empty);
		
		private string _PID;
		
		private string _SESSION_ID;
		
		private string _NRP_USER;
		
		private string _NRP;
		
		private string _TGL_LEMBUR;
		
		private string _AWAL_LEMBUR;
		
		private string _AKHIR_LEMBUR;
		
		private string _URAIAN_LEMBUR;
		
		private string _STATUS;
		
		private string _REMARK;
		
    #region Extensibility Method Definitions
    partial void OnLoaded();
    partial void OnValidate(System.Data.Linq.ChangeAction action);
    partial void OnCreated();
    partial void OnPIDChanging(string value);
    partial void OnPIDChanged();
    partial void OnSESSION_IDChanging(string value);
    partial void OnSESSION_IDChanged();
    partial void OnNRP_USERChanging(string value);
    partial void OnNRP_USERChanged();
    partial void OnNRPChanging(string value);
    partial void OnNRPChanged();
    partial void OnTGL_LEMBURChanging(string value);
    partial void OnTGL_LEMBURChanged();
    partial void OnAWAL_LEMBURChanging(string value);
    partial void OnAWAL_LEMBURChanged();
    partial void OnAKHIR_LEMBURChanging(string value);
    partial void OnAKHIR_LEMBURChanged();
    partial void OnURAIAN_LEMBURChanging(string value);
    partial void OnURAIAN_LEMBURChanged();
    partial void OnSTATUSChanging(string value);
    partial void OnSTATUSChanged();
    partial void OnREMARKChanging(string value);
    partial void OnREMARKChanged();
    #endregion
		
		public TBL_TEMP_SKL()
		{
			OnCreated();
		}
		
		[global::System.Data.Linq.Mapping.ColumnAttribute(Storage="_PID", DbType="VarChar(50) NOT NULL", CanBeNull=false, IsPrimaryKey=true)]
		public string PID
		{
			get
			{
				return this._PID;
			}
			set
			{
				if ((this._PID != value))
				{
					this.OnPIDChanging(value);
					this.SendPropertyChanging();
					this._PID = value;
					this.SendPropertyChanged("PID");
					this.OnPIDChanged();
				}
			}
		}
		
		[global::System.Data.Linq.Mapping.ColumnAttribute(Storage="_SESSION_ID", DbType="VarChar(50)")]
		public string SESSION_ID
		{
			get
			{
				return this._SESSION_ID;
			}
			set
			{
				if ((this._SESSION_ID != value))
				{
					this.OnSESSION_IDChanging(value);
					this.SendPropertyChanging();
					this._SESSION_ID = value;
					this.SendPropertyChanged("SESSION_ID");
					this.OnSESSION_IDChanged();
				}
			}
		}
		
		[global::System.Data.Linq.Mapping.ColumnAttribute(Storage="_NRP_USER", DbType="VarChar(50)")]
		public string NRP_USER
		{
			get
			{
				return this._NRP_USER;
			}
			set
			{
				if ((this._NRP_USER != value))
				{
					this.OnNRP_USERChanging(value);
					this.SendPropertyChanging();
					this._NRP_USER = value;
					this.SendPropertyChanged("NRP_USER");
					this.OnNRP_USERChanged();
				}
			}
		}
		
		[global::System.Data.Linq.Mapping.ColumnAttribute(Storage="_NRP", DbType="VarChar(50)")]
		public string NRP
		{
			get
			{
				return this._NRP;
			}
			set
			{
				if ((this._NRP != value))
				{
					this.OnNRPChanging(value);
					this.SendPropertyChanging();
					this._NRP = value;
					this.SendPropertyChanged("NRP");
					this.OnNRPChanged();
				}
			}
		}
		
		[global::System.Data.Linq.Mapping.ColumnAttribute(Storage="_TGL_LEMBUR", DbType="VarChar(50)")]
		public string TGL_LEMBUR
		{
			get
			{
				return this._TGL_LEMBUR;
			}
			set
			{
				if ((this._TGL_LEMBUR != value))
				{
					this.OnTGL_LEMBURChanging(value);
					this.SendPropertyChanging();
					this._TGL_LEMBUR = value;
					this.SendPropertyChanged("TGL_LEMBUR");
					this.OnTGL_LEMBURChanged();
				}
			}
		}
		
		[global::System.Data.Linq.Mapping.ColumnAttribute(Storage="_AWAL_LEMBUR", DbType="VarChar(50)")]
		public string AWAL_LEMBUR
		{
			get
			{
				return this._AWAL_LEMBUR;
			}
			set
			{
				if ((this._AWAL_LEMBUR != value))
				{
					this.OnAWAL_LEMBURChanging(value);
					this.SendPropertyChanging();
					this._AWAL_LEMBUR = value;
					this.SendPropertyChanged("AWAL_LEMBUR");
					this.OnAWAL_LEMBURChanged();
				}
			}
		}
		
		[global::System.Data.Linq.Mapping.ColumnAttribute(Storage="_AKHIR_LEMBUR", DbType="VarChar(50)")]
		public string AKHIR_LEMBUR
		{
			get
			{
				return this._AKHIR_LEMBUR;
			}
			set
			{
				if ((this._AKHIR_LEMBUR != value))
				{
					this.OnAKHIR_LEMBURChanging(value);
					this.SendPropertyChanging();
					this._AKHIR_LEMBUR = value;
					this.SendPropertyChanged("AKHIR_LEMBUR");
					this.OnAKHIR_LEMBURChanged();
				}
			}
		}
		
		[global::System.Data.Linq.Mapping.ColumnAttribute(Storage="_URAIAN_LEMBUR", DbType="VarChar(MAX)")]
		public string URAIAN_LEMBUR
		{
			get
			{
				return this._URAIAN_LEMBUR;
			}
			set
			{
				if ((this._URAIAN_LEMBUR != value))
				{
					this.OnURAIAN_LEMBURChanging(value);
					this.SendPropertyChanging();
					this._URAIAN_LEMBUR = value;
					this.SendPropertyChanged("URAIAN_LEMBUR");
					this.OnURAIAN_LEMBURChanged();
				}
			}
		}
		
		[global::System.Data.Linq.Mapping.ColumnAttribute(Storage="_STATUS", DbType="VarChar(2)")]
		public string STATUS
		{
			get
			{
				return this._STATUS;
			}
			set
			{
				if ((this._STATUS != value))
				{
					this.OnSTATUSChanging(value);
					this.SendPropertyChanging();
					this._STATUS = value;
					this.SendPropertyChanged("STATUS");
					this.OnSTATUSChanged();
				}
			}
		}
		
		[global::System.Data.Linq.Mapping.ColumnAttribute(Storage="_REMARK", DbType="VarChar(MAX)")]
		public string REMARK
		{
			get
			{
				return this._REMARK;
			}
			set
			{
				if ((this._REMARK != value))
				{
					this.OnREMARKChanging(value);
					this.SendPropertyChanging();
					this._REMARK = value;
					this.SendPropertyChanged("REMARK");
					this.OnREMARKChanged();
				}
			}
		}
		
		public event PropertyChangingEventHandler PropertyChanging;
		
		public event PropertyChangedEventHandler PropertyChanged;
		
		protected virtual void SendPropertyChanging()
		{
			if ((this.PropertyChanging != null))
			{
				this.PropertyChanging(this, emptyChangingEventArgs);
			}
		}
		
		protected virtual void SendPropertyChanged(String propertyName)
		{
			if ((this.PropertyChanged != null))
			{
				this.PropertyChanged(this, new PropertyChangedEventArgs(propertyName));
			}
		}
	}
	
	[global::System.Data.Linq.Mapping.TableAttribute(Name="UPLOADER.TBL_R_USER")]
	public partial class TBL_R_USER : INotifyPropertyChanging, INotifyPropertyChanged
	{
		
		private static PropertyChangingEventArgs emptyChangingEventArgs = new PropertyChangingEventArgs(String.Empty);
		
		private string _USER_ID;
		
		private string _EMPLOYEE_ID;
		
    #region Extensibility Method Definitions
    partial void OnLoaded();
    partial void OnValidate(System.Data.Linq.ChangeAction action);
    partial void OnCreated();
    partial void OnUSER_IDChanging(string value);
    partial void OnUSER_IDChanged();
    partial void OnEMPLOYEE_IDChanging(string value);
    partial void OnEMPLOYEE_IDChanged();
    #endregion
		
		public TBL_R_USER()
		{
			OnCreated();
		}
		
		[global::System.Data.Linq.Mapping.ColumnAttribute(Storage="_USER_ID", DbType="VarChar(50) NOT NULL", CanBeNull=false, IsPrimaryKey=true)]
		public string USER_ID
		{
			get
			{
				return this._USER_ID;
			}
			set
			{
				if ((this._USER_ID != value))
				{
					this.OnUSER_IDChanging(value);
					this.SendPropertyChanging();
					this._USER_ID = value;
					this.SendPropertyChanged("USER_ID");
					this.OnUSER_IDChanged();
				}
			}
		}
		
		[global::System.Data.Linq.Mapping.ColumnAttribute(Storage="_EMPLOYEE_ID", DbType="VarChar(50)")]
		public string EMPLOYEE_ID
		{
			get
			{
				return this._EMPLOYEE_ID;
			}
			set
			{
				if ((this._EMPLOYEE_ID != value))
				{
					this.OnEMPLOYEE_IDChanging(value);
					this.SendPropertyChanging();
					this._EMPLOYEE_ID = value;
					this.SendPropertyChanged("EMPLOYEE_ID");
					this.OnEMPLOYEE_IDChanged();
				}
			}
		}
		
		public event PropertyChangingEventHandler PropertyChanging;
		
		public event PropertyChangedEventHandler PropertyChanged;
		
		protected virtual void SendPropertyChanging()
		{
			if ((this.PropertyChanging != null))
			{
				this.PropertyChanging(this, emptyChangingEventArgs);
			}
		}
		
		protected virtual void SendPropertyChanged(String propertyName)
		{
			if ((this.PropertyChanged != null))
			{
				this.PropertyChanged(this, new PropertyChangedEventArgs(propertyName));
			}
		}
	}
	
	[global::System.Data.Linq.Mapping.TableAttribute(Name="UPLOADER.TBL_TEMP_ELIS")]
	public partial class TBL_TEMP_ELI : INotifyPropertyChanging, INotifyPropertyChanged
	{
		
		private static PropertyChangingEventArgs emptyChangingEventArgs = new PropertyChangingEventArgs(String.Empty);
		
		private int _PID;
		
		private string _SESSION_ID;
		
		private string _NRP;
		
		private string _INSPEKSI;
		
		private string _SIDAK;
		
		private string _BBS_PTO;
		
		private string _G_CARD;
		
		private string _TGL;
		
		private string _STATUS;
		
		private string _REMARK;
		
    #region Extensibility Method Definitions
    partial void OnLoaded();
    partial void OnValidate(System.Data.Linq.ChangeAction action);
    partial void OnCreated();
    partial void OnPIDChanging(int value);
    partial void OnPIDChanged();
    partial void OnSESSION_IDChanging(string value);
    partial void OnSESSION_IDChanged();
    partial void OnNRPChanging(string value);
    partial void OnNRPChanged();
    partial void OnINSPEKSIChanging(string value);
    partial void OnINSPEKSIChanged();
    partial void OnSIDAKChanging(string value);
    partial void OnSIDAKChanged();
    partial void OnBBS_PTOChanging(string value);
    partial void OnBBS_PTOChanged();
    partial void OnG_CARDChanging(string value);
    partial void OnG_CARDChanged();
    partial void OnTGLChanging(string value);
    partial void OnTGLChanged();
    partial void OnSTATUSChanging(string value);
    partial void OnSTATUSChanged();
    partial void OnREMARKChanging(string value);
    partial void OnREMARKChanged();
    #endregion
		
		public TBL_TEMP_ELI()
		{
			OnCreated();
		}
		
		[global::System.Data.Linq.Mapping.ColumnAttribute(Storage="_PID", AutoSync=AutoSync.OnInsert, DbType="Int NOT NULL IDENTITY", IsPrimaryKey=true, IsDbGenerated=true)]
		public int PID
		{
			get
			{
				return this._PID;
			}
			set
			{
				if ((this._PID != value))
				{
					this.OnPIDChanging(value);
					this.SendPropertyChanging();
					this._PID = value;
					this.SendPropertyChanged("PID");
					this.OnPIDChanged();
				}
			}
		}
		
		[global::System.Data.Linq.Mapping.ColumnAttribute(Storage="_SESSION_ID", DbType="VarChar(50)")]
		public string SESSION_ID
		{
			get
			{
				return this._SESSION_ID;
			}
			set
			{
				if ((this._SESSION_ID != value))
				{
					this.OnSESSION_IDChanging(value);
					this.SendPropertyChanging();
					this._SESSION_ID = value;
					this.SendPropertyChanged("SESSION_ID");
					this.OnSESSION_IDChanged();
				}
			}
		}
		
		[global::System.Data.Linq.Mapping.ColumnAttribute(Storage="_NRP", DbType="VarChar(15)")]
		public string NRP
		{
			get
			{
				return this._NRP;
			}
			set
			{
				if ((this._NRP != value))
				{
					this.OnNRPChanging(value);
					this.SendPropertyChanging();
					this._NRP = value;
					this.SendPropertyChanged("NRP");
					this.OnNRPChanged();
				}
			}
		}
		
		[global::System.Data.Linq.Mapping.ColumnAttribute(Storage="_INSPEKSI", DbType="VarChar(3)")]
		public string INSPEKSI
		{
			get
			{
				return this._INSPEKSI;
			}
			set
			{
				if ((this._INSPEKSI != value))
				{
					this.OnINSPEKSIChanging(value);
					this.SendPropertyChanging();
					this._INSPEKSI = value;
					this.SendPropertyChanged("INSPEKSI");
					this.OnINSPEKSIChanged();
				}
			}
		}
		
		[global::System.Data.Linq.Mapping.ColumnAttribute(Storage="_SIDAK", DbType="VarChar(3)")]
		public string SIDAK
		{
			get
			{
				return this._SIDAK;
			}
			set
			{
				if ((this._SIDAK != value))
				{
					this.OnSIDAKChanging(value);
					this.SendPropertyChanging();
					this._SIDAK = value;
					this.SendPropertyChanged("SIDAK");
					this.OnSIDAKChanged();
				}
			}
		}
		
		[global::System.Data.Linq.Mapping.ColumnAttribute(Storage="_BBS_PTO", DbType="VarChar(3)")]
		public string BBS_PTO
		{
			get
			{
				return this._BBS_PTO;
			}
			set
			{
				if ((this._BBS_PTO != value))
				{
					this.OnBBS_PTOChanging(value);
					this.SendPropertyChanging();
					this._BBS_PTO = value;
					this.SendPropertyChanged("BBS_PTO");
					this.OnBBS_PTOChanged();
				}
			}
		}
		
		[global::System.Data.Linq.Mapping.ColumnAttribute(Storage="_G_CARD", DbType="VarChar(3)")]
		public string G_CARD
		{
			get
			{
				return this._G_CARD;
			}
			set
			{
				if ((this._G_CARD != value))
				{
					this.OnG_CARDChanging(value);
					this.SendPropertyChanging();
					this._G_CARD = value;
					this.SendPropertyChanged("G_CARD");
					this.OnG_CARDChanged();
				}
			}
		}
		
		[global::System.Data.Linq.Mapping.ColumnAttribute(Storage="_TGL", DbType="VarChar(20)")]
		public string TGL
		{
			get
			{
				return this._TGL;
			}
			set
			{
				if ((this._TGL != value))
				{
					this.OnTGLChanging(value);
					this.SendPropertyChanging();
					this._TGL = value;
					this.SendPropertyChanged("TGL");
					this.OnTGLChanged();
				}
			}
		}
		
		[global::System.Data.Linq.Mapping.ColumnAttribute(Storage="_STATUS", DbType="VarChar(2)")]
		public string STATUS
		{
			get
			{
				return this._STATUS;
			}
			set
			{
				if ((this._STATUS != value))
				{
					this.OnSTATUSChanging(value);
					this.SendPropertyChanging();
					this._STATUS = value;
					this.SendPropertyChanged("STATUS");
					this.OnSTATUSChanged();
				}
			}
		}
		
		[global::System.Data.Linq.Mapping.ColumnAttribute(Storage="_REMARK", DbType="VarChar(MAX)")]
		public string REMARK
		{
			get
			{
				return this._REMARK;
			}
			set
			{
				if ((this._REMARK != value))
				{
					this.OnREMARKChanging(value);
					this.SendPropertyChanging();
					this._REMARK = value;
					this.SendPropertyChanged("REMARK");
					this.OnREMARKChanged();
				}
			}
		}
		
		public event PropertyChangingEventHandler PropertyChanging;
		
		public event PropertyChangedEventHandler PropertyChanged;
		
		protected virtual void SendPropertyChanging()
		{
			if ((this.PropertyChanging != null))
			{
				this.PropertyChanging(this, emptyChangingEventArgs);
			}
		}
		
		protected virtual void SendPropertyChanged(String propertyName)
		{
			if ((this.PropertyChanged != null))
			{
				this.PropertyChanged(this, new PropertyChangedEventArgs(propertyName));
			}
		}
	}
	
	[global::System.Data.Linq.Mapping.TableAttribute(Name="UPLOADER.TBL_TEMP_RITASE_LKM")]
	public partial class TBL_TEMP_RITASE_LKM : INotifyPropertyChanging, INotifyPropertyChanged
	{
		
		private static PropertyChangingEventArgs emptyChangingEventArgs = new PropertyChangingEventArgs(String.Empty);
		
		private int _PID;
		
		private string _SESSION_ID;
		
		private string _NRP;
		
		private string _TANGGAL;
		
		private string _RITASE;
		
		private string _LKM;
		
		private string _JKP;
		
		private string _STATUS;
		
		private string _REMARK;
		
    #region Extensibility Method Definitions
    partial void OnLoaded();
    partial void OnValidate(System.Data.Linq.ChangeAction action);
    partial void OnCreated();
    partial void OnPIDChanging(int value);
    partial void OnPIDChanged();
    partial void OnSESSION_IDChanging(string value);
    partial void OnSESSION_IDChanged();
    partial void OnNRPChanging(string value);
    partial void OnNRPChanged();
    partial void OnTANGGALChanging(string value);
    partial void OnTANGGALChanged();
    partial void OnRITASEChanging(string value);
    partial void OnRITASEChanged();
    partial void OnLKMChanging(string value);
    partial void OnLKMChanged();
    partial void OnJKPChanging(string value);
    partial void OnJKPChanged();
    partial void OnSTATUSChanging(string value);
    partial void OnSTATUSChanged();
    partial void OnREMARKChanging(string value);
    partial void OnREMARKChanged();
    #endregion
		
		public TBL_TEMP_RITASE_LKM()
		{
			OnCreated();
		}
		
		[global::System.Data.Linq.Mapping.ColumnAttribute(Storage="_PID", AutoSync=AutoSync.OnInsert, DbType="Int NOT NULL IDENTITY", IsPrimaryKey=true, IsDbGenerated=true)]
		public int PID
		{
			get
			{
				return this._PID;
			}
			set
			{
				if ((this._PID != value))
				{
					this.OnPIDChanging(value);
					this.SendPropertyChanging();
					this._PID = value;
					this.SendPropertyChanged("PID");
					this.OnPIDChanged();
				}
			}
		}
		
		[global::System.Data.Linq.Mapping.ColumnAttribute(Storage="_SESSION_ID", DbType="VarChar(50) NOT NULL", CanBeNull=false)]
		public string SESSION_ID
		{
			get
			{
				return this._SESSION_ID;
			}
			set
			{
				if ((this._SESSION_ID != value))
				{
					this.OnSESSION_IDChanging(value);
					this.SendPropertyChanging();
					this._SESSION_ID = value;
					this.SendPropertyChanged("SESSION_ID");
					this.OnSESSION_IDChanged();
				}
			}
		}
		
		[global::System.Data.Linq.Mapping.ColumnAttribute(Storage="_NRP", DbType="VarChar(20)")]
		public string NRP
		{
			get
			{
				return this._NRP;
			}
			set
			{
				if ((this._NRP != value))
				{
					this.OnNRPChanging(value);
					this.SendPropertyChanging();
					this._NRP = value;
					this.SendPropertyChanged("NRP");
					this.OnNRPChanged();
				}
			}
		}
		
		[global::System.Data.Linq.Mapping.ColumnAttribute(Storage="_TANGGAL", DbType="VarChar(20)")]
		public string TANGGAL
		{
			get
			{
				return this._TANGGAL;
			}
			set
			{
				if ((this._TANGGAL != value))
				{
					this.OnTANGGALChanging(value);
					this.SendPropertyChanging();
					this._TANGGAL = value;
					this.SendPropertyChanged("TANGGAL");
					this.OnTANGGALChanged();
				}
			}
		}
		
		[global::System.Data.Linq.Mapping.ColumnAttribute(Storage="_RITASE", DbType="VarChar(10)")]
		public string RITASE
		{
			get
			{
				return this._RITASE;
			}
			set
			{
				if ((this._RITASE != value))
				{
					this.OnRITASEChanging(value);
					this.SendPropertyChanging();
					this._RITASE = value;
					this.SendPropertyChanged("RITASE");
					this.OnRITASEChanged();
				}
			}
		}
		
		[global::System.Data.Linq.Mapping.ColumnAttribute(Storage="_LKM", DbType="VarChar(10)")]
		public string LKM
		{
			get
			{
				return this._LKM;
			}
			set
			{
				if ((this._LKM != value))
				{
					this.OnLKMChanging(value);
					this.SendPropertyChanging();
					this._LKM = value;
					this.SendPropertyChanged("LKM");
					this.OnLKMChanged();
				}
			}
		}
		
		[global::System.Data.Linq.Mapping.ColumnAttribute(Storage="_JKP", DbType="VarChar(10)")]
		public string JKP
		{
			get
			{
				return this._JKP;
			}
			set
			{
				if ((this._JKP != value))
				{
					this.OnJKPChanging(value);
					this.SendPropertyChanging();
					this._JKP = value;
					this.SendPropertyChanged("JKP");
					this.OnJKPChanged();
				}
			}
		}
		
		[global::System.Data.Linq.Mapping.ColumnAttribute(Storage="_STATUS", DbType="VarChar(2)")]
		public string STATUS
		{
			get
			{
				return this._STATUS;
			}
			set
			{
				if ((this._STATUS != value))
				{
					this.OnSTATUSChanging(value);
					this.SendPropertyChanging();
					this._STATUS = value;
					this.SendPropertyChanged("STATUS");
					this.OnSTATUSChanged();
				}
			}
		}
		
		[global::System.Data.Linq.Mapping.ColumnAttribute(Storage="_REMARK", DbType="VarChar(MAX)")]
		public string REMARK
		{
			get
			{
				return this._REMARK;
			}
			set
			{
				if ((this._REMARK != value))
				{
					this.OnREMARKChanging(value);
					this.SendPropertyChanging();
					this._REMARK = value;
					this.SendPropertyChanged("REMARK");
					this.OnREMARKChanged();
				}
			}
		}
		
		public event PropertyChangingEventHandler PropertyChanging;
		
		public event PropertyChangedEventHandler PropertyChanged;
		
		protected virtual void SendPropertyChanging()
		{
			if ((this.PropertyChanging != null))
			{
				this.PropertyChanging(this, emptyChangingEventArgs);
			}
		}
		
		protected virtual void SendPropertyChanged(String propertyName)
		{
			if ((this.PropertyChanged != null))
			{
				this.PropertyChanged(this, new PropertyChangedEventArgs(propertyName));
			}
		}
	}
}
#pragma warning restore 1591
