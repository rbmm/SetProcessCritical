#include "stdafx.h"

_NT_BEGIN
#include "..\winz\window.h"
#include "..\winz\ctrl.h"
#include "..\inc\initterm.h"
#include "resource.h"

BEGIN_PRIVILEGES(tp_tcb_dbg, 2)
	LAA(SE_TCB_PRIVILEGE),
	LAA(SE_DEBUG_PRIVILEGE),
END_PRIVILEGES

const OBJECT_ATTRIBUTES zoa = { sizeof(zoa) };
volatile const UCHAR guz = 0;

union ProcessFlags {
	ULONG Flags;
	struct {
		ULONG IsProtectedProcess : 1;
		ULONG IsWow64Process : 1;
		ULONG IsProcessDeleting : 1;
		ULONG IsCrossSessionCreate : 1;
		ULONG IsFrozen : 1;
		ULONG IsBackground : 1;
		ULONG IsStronglyNamed : 1;
		ULONG IsSecureProcess : 1;
		ULONG IsSubsystemProcess : 1;
		//////////////////////////////////////////////////////////////////////////
		ULONG IsBreakOnTermination : 1;
		ULONG IsInJob : 1;
		ULONG IsAppContainer : 1;
		ULONG SpareBits : 20;
	};
};

C_ASSERT(sizeof(ProcessFlags) == sizeof(ULONG));

enum { 
	iNumber, 
	iPID, 
	iFrom, 
	iName, 
	iSession,
	iLevel, 
	iBreakOnTermination,
	iWow64Process,
	iAppContainer,
	iInJob,
	iProtectedProcess,
	iCrossSessionCreate,
	iStronglyNamed,
	iFrozen,
	iBackground,
	iSubsystemProcess,
	iProcessDeleting,
	iSecureProcess,
	iMax
};

void ShowErrorBox(HWND hwnd, HRESULT dwError, PCWSTR pzCaption, UINT uType = MB_OK)
{
	PWSTR psz;
	ULONG dwFlags, errType = uType & MB_ICONMASK;
	HMODULE hmod;	

	if ((dwError & FACILITY_NT_BIT) || (0 > dwError && HRESULT_FACILITY(dwError) == FACILITY_NULL))
	{
		dwError &= ~FACILITY_NT_BIT;
		static HMODULE s_hmod;
		if (!s_hmod)
		{
			s_hmod = GetModuleHandle(L"ntdll");
		}
		hmod = s_hmod;
		dwFlags = FORMAT_MESSAGE_IGNORE_INSERTS | FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_HMODULE;

		if (!errType)
		{
			static const UINT s_errType[] = { MB_ICONINFORMATION, MB_ICONINFORMATION, MB_ICONWARNING, MB_ICONERROR };
			uType |= s_errType[(ULONG)dwError >> 30];
		}
	}
	else
	{
		hmod = 0;
		dwFlags = FORMAT_MESSAGE_IGNORE_INSERTS | FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM;
		if (!errType)
		{
			uType |= dwError ? MB_ICONERROR : MB_ICONINFORMATION;
		}
	}

	if (FormatMessageW(dwFlags, hmod, dwError, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (PWSTR)&psz, 0, 0))
	{
		MessageBoxW(hwnd, psz, pzCaption, uType);
		LocalFree(psz);
	}
}

extern const SECURITY_QUALITY_OF_SERVICE sqos = {
	sizeof (sqos), SecurityImpersonation, SECURITY_DYNAMIC_TRACKING, FALSE
};

extern const OBJECT_ATTRIBUTES oa_sqos = { sizeof(oa_sqos), 0, 0, 0, 0, const_cast<SECURITY_QUALITY_OF_SERVICE*>(&sqos) };

NTSTATUS GetToken(PVOID buf, const TOKEN_PRIVILEGES* RequiredSet)
{
	NTSTATUS status;

	union {
		PVOID pv;
		PBYTE pb;
		PSYSTEM_PROCESS_INFORMATION pspi;
	};

	pv = buf;
	ULONG NextEntryOffset = 0;

	do 
	{
		pb += NextEntryOffset;

		HANDLE hProcess, hToken, hNewToken;

		CLIENT_ID ClientId = { pspi->UniqueProcessId };

		if (ClientId.UniqueProcess)
		{
			if (0 <= NtOpenProcess(&hProcess, PROCESS_QUERY_LIMITED_INFORMATION, 
				const_cast<POBJECT_ATTRIBUTES>(&oa_sqos), &ClientId))
			{
				status = NtOpenProcessToken(hProcess, TOKEN_DUPLICATE, &hToken);

				NtClose(hProcess);

				if (0 <= status)
				{
					status = NtDuplicateToken(hToken, TOKEN_ADJUST_PRIVILEGES|TOKEN_IMPERSONATE, 
						const_cast<POBJECT_ATTRIBUTES>(&oa_sqos), FALSE, TokenImpersonation, &hNewToken);

					NtClose(hToken);

					if (0 <= status)
					{
						status = NtAdjustPrivilegesToken(hNewToken, FALSE, const_cast<PTOKEN_PRIVILEGES>(RequiredSet), 0, 0, 0);

						if (STATUS_SUCCESS == status)	
						{
							status = NtSetInformationThread(NtCurrentThread(), ThreadImpersonationToken, &hNewToken, sizeof(hNewToken));
						}

						NtClose(hNewToken);

						if (STATUS_SUCCESS == status)
						{
							return STATUS_SUCCESS;
						}
					}
				}
			}
		}

	} while (NextEntryOffset = pspi->NextEntryOffset);

	return STATUS_UNSUCCESSFUL;
}

inline void set_Number(SYSTEM_PROCESS_INFORMATION* pspi, ULONG il)
{
	pspi->SpareLi2.LowPart = il;
}

inline ULONG get_Number(const SYSTEM_PROCESS_INFORMATION* pspi)
{
	return pspi->SpareLi2.LowPart;
}

inline void set_IL(SYSTEM_PROCESS_INFORMATION* pspi, ULONG il)
{
	pspi->SpareLi1.LowPart = il;
}

inline ULONG get_IL(const SYSTEM_PROCESS_INFORMATION* pspi)
{
	return pspi->SpareLi1.LowPart;
}

inline void set_ProStatus(SYSTEM_PROCESS_INFORMATION* pspi, NTSTATUS status)
{
	pspi->SpareLi1.HighPart = status;
}

inline NTSTATUS get_ProStatus(const SYSTEM_PROCESS_INFORMATION* pspi)
{
	return pspi->SpareLi1.HighPart;
}

inline ProcessFlags* GetProcessFlags(const SYSTEM_PROCESS_INFORMATION* pspi)
{
	return (ProcessFlags*)&pspi->SpareLi2.HighPart;
}

class ProcessList
{
	PVOID _buf = 0;
	PSYSTEM_PROCESS_INFORMATION* _Items = 0;
	int(__cdecl* _sortfn)(PSYSTEM_PROCESS_INFORMATION& p, PSYSTEM_PROCESS_INFORMATION& q) = 0;
	ULONG _count = 0;

	NTSTATUS CreatePlain();

	void InitVector()
	{
		union {
			PVOID buf;
			PBYTE pb;
			PSYSTEM_PROCESS_INFORMATION pspi;
		};

		PSYSTEM_PROCESS_INFORMATION* Items = _Items;
		buf = _buf;

		ULONG NextEntryOffset = 0;
		do 
		{
			pb += NextEntryOffset;
			if (pspi->UniqueProcessId)
			{
				*Items++ = pspi;
			}

		} while (NextEntryOffset = pspi->NextEntryOffset);
	}

public:

	~ProcessList()
	{
		if (_Items) delete [] _Items;
		if (_buf) delete [] _buf;
	}

	const SYSTEM_PROCESS_INFORMATION* operator[](ULONG i)
	{
		return i < _count ? _Items[i] : 0;
	}

	void operator()(int(__cdecl* sortfn)(PSYSTEM_PROCESS_INFORMATION& p, PSYSTEM_PROCESS_INFORMATION& q))
	{
		if (_count)
		{
			if (sortfn)
			{
				qsort(_Items, _count, sizeof(PSYSTEM_PROCESS_INFORMATION), (QSORTFN)sortfn);
			}
			else
			{
				InitVector();
			}
		}

		_sortfn = sortfn;
	}

	ULONG operator()()
	{
		return _count;
	}

	NTSTATUS Create();
};

NTSTATUS ProcessList::Create()
{
	ULONG count = _count;

	NTSTATUS status = CreatePlain();

	if (0 <= status)
	{
		if (count != _count)
		{
			delete[] _Items, _Items = 0;

			if (!(_Items = new PSYSTEM_PROCESS_INFORMATION [_count]))
			{
				_count = 0, delete[] _buf, _buf = 0;
			}
		}
	}

	if (count = _count)
	{
		InitVector();

		if (_sortfn)
		{
			qsort(_Items, count, sizeof(PSYSTEM_PROCESS_INFORMATION), (QSORTFN)_sortfn);
		}
	}

	return status;
}

NTSTATUS ProcessList::CreatePlain()
{
	if (_buf)
	{
		delete [] _buf;
		_buf = 0, _count = 0;
	}

	NTSTATUS status;

	union {
		PVOID buf;
		PBYTE pb;
		PSYSTEM_PROCESS_INFORMATION pspi;
	};

	union {
		PVOID pv_ptml;
		PTOKEN_MANDATORY_LABEL ptml;
	};

	PROCESS_EXTENDED_BASIC_INFORMATION pebi = { sizeof(pebi) };

	PVOID stack = alloca(guz);
	ULONG cbHeap = 0x10000, count = 0, cb = 0, rcb = sizeof(TOKEN_MANDATORY_LABEL) + SECURITY_SID_SIZE(1), n = 0;

	do 
	{
		status = STATUS_INSUFFICIENT_RESOURCES;

		if (buf = new UCHAR[cbHeap += 0x1000])
		{
			if (0 <= (status = NtQuerySystemInformation(SystemProcessInformation, buf, cbHeap, &cbHeap)))
			{
				_buf = buf;

				HANDLE hProcess, hToken;
				GetToken(buf, &tp_tcb_dbg);

				ULONG NextEntryOffset = 0;

				do 
				{
					pb += NextEntryOffset;

					CLIENT_ID cid = { pspi->UniqueProcessId };

					if (!cid.UniqueProcess) continue;

					count++;

					ProcessFlags* pf = GetProcessFlags(pspi);

					pf->Flags = 0;

					NTSTATUS s = NtOpenProcess(&hProcess, PROCESS_QUERY_LIMITED_INFORMATION, const_cast<POBJECT_ATTRIBUTES>(&zoa), &cid);

					set_ProStatus(pspi, s);
					set_Number(pspi, n++);
					
					if (0 <= s)
					{
						if (0 <= (s = NtQueryInformationProcess(hProcess, ProcessBasicInformation, &pebi, sizeof(pebi), 0)))
						{
							pebi.SpareBits = 0;
							pf->Flags = pebi.Flags;
						}
						else
						{
							__nop();
						}

						union {
							PVOID wow;
							BOOL bInJob;
							BOOL bIsAppContainer;
							ULONG fBreakOnTermination;
						};

						if (0 <= (s = NtQueryInformationProcess(hProcess, ProcessBreakOnTermination, 
							&fBreakOnTermination, sizeof(fBreakOnTermination), 0)))
						{
							if (fBreakOnTermination) pf->IsBreakOnTermination = TRUE;
						}
						else
						{
							__nop();
						}

						if (0 <= (s = NtQueryInformationProcess(hProcess, ProcessWow64Information, &wow, sizeof(wow), 0)))
						{
							if (wow) pf->IsWow64Process = TRUE;
						}
						else
						{
							__nop();
						}

						if (IsProcessInJob(hProcess, 0, &bInJob))
						{
							if (bInJob) pf->IsInJob = TRUE;
						}
						else
						{
							__nop();
						}

						if (0 <= (s = NtOpenProcessToken(hProcess, TOKEN_QUERY, &hToken)))
						{
							if (0 <= (status = NtQueryInformationToken(hToken, TokenIsAppContainer, 
								&bIsAppContainer, sizeof(bIsAppContainer), &rcb)))
							{
								if (bIsAppContainer)
								{
									pf->IsAppContainer = TRUE;
								}
							}

							do 
							{
								if (cb < rcb) cb = RtlPointerToOffset(pv_ptml = alloca(rcb - cb), stack);

								if (0 <= (status = NtQueryInformationToken(hToken, TokenIntegrityLevel, pv_ptml, cb, &rcb)))
								{
									if (*GetSidSubAuthorityCount(ptml->Label.Sid) == 1)
									{
										set_IL(pspi, *GetSidSubAuthority(ptml->Label.Sid, 0));
									}
								}

							} while (status == STATUS_BUFFER_TOO_SMALL);

							NtClose(hToken);
						}
						else
						{
							__nop();
						}

						NtClose(hProcess);
					}
					else
					{
						__nop();
					}

				} while (NextEntryOffset = pspi->NextEntryOffset);

				NtSetInformationThread(NtCurrentThread(), ThreadImpersonationToken, &(hToken = 0), sizeof(hToken));

				_count = count;

				return STATUS_SUCCESS;
			}

			delete [] buf;
		}

	} while (status == STATUS_INFO_LENGTH_MISMATCH);

	return status;
}

//////////////////////////////////////////////////////////////////////////
class CDlg : public ZDlg, CIcons
{
	ProcessList _pl;
	ULONG _iItem = MAXULONG;
	ULONG _iSubItem = 0;
	int _s[iMax];

	void GetItemInfo(LVITEM& Item);
	void GetTipInfo(NMLVGETINFOTIP* pti);
	bool OnColumClick(ULONG iSubItem);
	void OnColumClick(ULONG iSubItem, HWND hwndLV);

	void Refresh(HWND hwndDlg, HWND hwnd)
	{
		_pl.Create();
		ListView_SetItemCountEx(hwnd, _pl(), 0);
		InvalidateRect(hwnd, 0, TRUE);
		OnItemSelected(_iItem, hwndDlg);
	}

	void OnInitDialog(HWND hwndDlg)
	{
		SetIcons(hwndDlg, (HINSTANCE)&__ImageBase, MAKEINTRESOURCEW(IDI_ICON_G));

		HWND hwnd = GetDlgItem(hwndDlg, IDC_LIST1);

		ListView_SetExtendedListViewStyle(hwnd, LVS_EX_INFOTIP | LVS_EX_BORDERSELECT | LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER);

		SIZE size = { };

		if (HDC hdc = GetDC(hwnd))
		{
			HGDIOBJ o = SelectObject(hdc, (HGDIOBJ)SendMessage(hwnd, WM_GETFONT, 0, 0));
			GetTextExtentPoint32(hdc, L"W", 1, &size);
			SelectObject(hdc, o);
			ReleaseDC(hwnd, hdc);
		}

		RtlFillMemoryUlong(_s, sizeof(_s), (ULONG)-1);

		LVCOLUMN lvc = { LVCF_FMT | LVCF_WIDTH | LVCF_TEXT | LVCF_SUBITEM, LVCFMT_LEFT };

		static const PCWSTR headers[] = {
			L"   #", 
			L"  ID", 
			L"From", 
			L" Name ", 
			L"S_id", 
			L" IL ", 
			L" T ", 
			L" W ", 
			L" A ",
			L" J ",
			L" P ", 
			L" C ", 
			L" N ", 
			L" F ",
			L" B ", 
			L" Y ", 
			L" D ", 
			L" S ", 
		};

		static const ULONG lens[] = { 8, 8, 8, 26, 6, 8, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5 };

		C_ASSERT(_countof(headers) == _countof(lens));

		do
		{
			lvc.pszText = const_cast<PWSTR>(headers[lvc.iSubItem]), lvc.cx = lens[lvc.iSubItem] * size.cx;
			ListView_InsertColumn(hwnd, lvc.iSubItem, &lvc);
		} while (++lvc.iSubItem < _countof(headers));

		lvc.mask = LVCF_FMT;
		lvc.fmt = LVCFMT_LEFT|HDF_SORTUP;
		ListView_SetColumn(hwnd, 0, &lvc);

		int xy = size.cy < 24 ? 16 : 24;

		if (HIMAGELIST himl = ImageList_Create(xy, xy, ILC_COLOR32, 3, 0))
		{
			static const UINT iid[] = { IDI_ICON_R, IDI_ICON_G, IDI_ICON_B };

			int n = _countof(iid);
			do
			{
				if (HICON hi = (HICON)LoadImageW((HINSTANCE)&__ImageBase, MAKEINTRESOURCE(iid[--n]), IMAGE_ICON, xy, xy, LR_CREATEDIBSECTION))
				{
					ImageList_ReplaceIcon(himl, -1, hi);
					DestroyIcon(hi);
				}
			} while (n);

			ListView_SetImageList(hwnd, himl, LVSIL_SMALL);
		}

		ListView_SetExtendedListViewStyle(hwnd, 
			LVS_EX_FULLROWSELECT|LVS_EX_HEADERDRAGDROP|LVS_EX_LABELTIP|LVS_EX_DOUBLEBUFFER|LVS_EX_INFOTIP);

		Refresh(hwndDlg, hwnd);
	}

	virtual INT_PTR DialogProc(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
	{
		switch (uMsg)
		{
		case WM_INITDIALOG:
			OnInitDialog(hwndDlg);
			break;

		case WM_COMMAND:
			switch (wParam)
			{
			case IDCANCEL:
				EndDialog(hwndDlg, 0);
				break;
			case IDC_BUTTON1:
				Refresh(hwndDlg, GetDlgItem(hwndDlg, IDC_LIST1));
				break;
			case IDC_BUTTON2:
				Toggle(hwndDlg);
				break;
			}
			break;
		case WM_NOTIFY:
			switch (reinterpret_cast<NMHDR*>(lParam)->code)
			{
			case LVN_GETDISPINFO:
				GetItemInfo(reinterpret_cast<NMLVDISPINFO*>(lParam)->item);
				break;
			case LVN_GETINFOTIP:
				GetTipInfo(reinterpret_cast<NMLVGETINFOTIP*>(lParam));
				break;
			case LVN_COLUMNCLICK:
				OnColumClick(reinterpret_cast<NMLISTVIEW*>(lParam)->iSubItem, reinterpret_cast<NMHDR*>(lParam)->hwndFrom);
				break;
			case LVN_ITEMCHANGED:
				if (LVIF_STATE & reinterpret_cast<NMLISTVIEW*>(lParam)->uChanged)
				{
					UINT uNewState = reinterpret_cast<NMLISTVIEW*>(lParam)->uNewState & LVIS_SELECTED;
					UINT uOldState = reinterpret_cast<NMLISTVIEW*>(lParam)->uOldState & LVIS_SELECTED;

					if (uNewState != uOldState)
					{
						ULONG iItem = reinterpret_cast<NMLISTVIEW*>(lParam)->iItem;
						_iItem = iItem;

						OnItemSelected(iItem, hwndDlg);
					}
				}
				break;
			}
			break;
		}

		return __super::DialogProc(hwndDlg, uMsg, wParam, lParam);
	}

	void Toggle(HWND hwndDlg)
	{
		ULONG iItem = _iItem;
		NTSTATUS status = STATUS_NOT_FOUND;
		if (const SYSTEM_PROCESS_INFORMATION* pspi = _pl[iItem])
		{
			CLIENT_ID cid = { (HANDLE)pspi->UniqueProcessId };
			HANDLE hProcess;
			if (0 <= (status = NtOpenProcess(&hProcess, PROCESS_SET_INFORMATION, 
				const_cast<OBJECT_ATTRIBUTES*>(&zoa), &cid)))
			{
				BOOL bBreak = !GetProcessFlags(pspi)->IsBreakOnTermination;
				
				if (0 <= (status = NtSetInformationProcess(hProcess, ProcessBreakOnTermination, &bBreak, sizeof(bBreak))))
				{
					GetProcessFlags(pspi)->IsBreakOnTermination = bBreak;

					HWND hwndLV = GetDlgItem(hwndDlg, IDC_LIST1);
					RECT rc {LVIR_BOUNDS};
					if (SendMessageW(hwndLV, LVM_GETITEMRECT, iItem, (LPARAM)&rc))
					{
						InvalidateRect(hwndLV, &rc, 0);
					}
				}

				NtClose(hProcess);
			}
		}	

		ShowErrorBox(hwndDlg, status ? HRESULT_FROM_NT(status) : S_OK, L"ProcessBreakOnTermination");
	}

	void OnItemSelected(ULONG iItem, HWND hwndDlg)
	{
		EnableWindow(GetDlgItem(hwndDlg, IDC_BUTTON2), iItem < _pl());
		SetStatus(iItem, hwndDlg);
	}

	void SetStatus(ULONG iItem, HWND hwndDlg)
	{
		if (const SYSTEM_PROCESS_INFORMATION* pspi = _pl[iItem])
		{
			TIME_FIELDS tf;
			LARGE_INTEGER locatime;
			RtlSystemTimeToLocalTime(&pspi->CreateTime, &locatime);
			RtlTimeToTimeFields(&locatime, &tf);

			char sz[32];
			DWORD s = (DWORD)(pspi->WorkingSetSize >> 10);
			if (s < 1000)
			{
				sprintf(sz, "%u", s);
			}
			else
			{
				sprintf(sz, "%u,%03u", s /1000, s % 1000);
			}
			WCHAR wz[128];
			swprintf_s(wz, _countof(wz), L"Threads=%d | Handles=%u | %SK | %d-%02d-%02d %02d:%02d:%02d",
				pspi->NumberOfThreads, pspi->HandleCount, sz, 
				tf.Year, tf.Month, tf.Day, tf.Hour, tf.Minute, tf.Second);

			SetDlgItemTextW(hwndDlg, IDC_STATIC1, wz);
			return;
		}

		SetDlgItemTextW(hwndDlg, IDC_STATIC1, L"");
	}
};

void CDlg::GetItemInfo(LVITEM& Item)
{
	if (const SYSTEM_PROCESS_INFORMATION* pspi = _pl[Item.iItem])
	{
		ProcessFlags* pf = GetProcessFlags(pspi);

		if (Item.mask & LVIF_IMAGE)
		{
			int iImage = I_IMAGENONE;

			if (0 > get_ProStatus(pspi))
			{
				iImage = 2;//red
			}
			else if (pf->IsBreakOnTermination)
			{
				iImage = 0;//blue
			}
			else
			{
				iImage = 1;//green
			}

			Item.iImage = iImage;
		}

		if (Item.mask & LVIF_TEXT)
		{
			static const PCWSTR yn[] = { L"", L" *" };

			PCWSTR pszText = L"";

			switch (Item.iSubItem)
			{
			case iNumber:
				swprintf_s(Item.pszText, Item.cchTextMax, L"%03u", get_Number(pspi));
				return;
			case iPID:
				swprintf_s(Item.pszText, Item.cchTextMax, L"%u", (ULONG)(ULONG_PTR)pspi->UniqueProcessId);
				return;
			case iFrom:
				swprintf_s(Item.pszText, Item.cchTextMax, L"%u", (ULONG)(ULONG_PTR)pspi->InheritedFromUniqueProcessId);
				return;
			case iName:
				swprintf_s(Item.pszText, Item.cchTextMax, L"%wZ", &pspi->ImageName);
				return;
			case iSession:
				swprintf_s(Item.pszText, Item.cchTextMax, L"%x", pspi->SessionId);
				return;
			case iLevel:
				swprintf_s(Item.pszText, Item.cchTextMax, L" %04x", get_IL(pspi));
				return;
			case iAppContainer:
				pszText = yn[pf->IsAppContainer];
				break;
			case iBreakOnTermination:
				pszText = yn[pf->IsBreakOnTermination];
				break;
			case iInJob:
				pszText = yn[pf->IsInJob];
				break;
			case iWow64Process:
				pszText = yn[pf->IsWow64Process];
				break;
			case iSecureProcess:
				pszText = yn[pf->IsSecureProcess];
				break;
			case iSubsystemProcess:
				pszText = yn[pf->IsSubsystemProcess];
				break;
			case iProcessDeleting:
				pszText = yn[pf->IsProcessDeleting];
				break;
			case iProtectedProcess:
				pszText = yn[pf->IsProtectedProcess];
				break;
			case iCrossSessionCreate:
				pszText = yn[pf->IsCrossSessionCreate];
				break;
			case iBackground:
				pszText = yn[pf->IsBackground];
				break;
			case iStronglyNamed:
				pszText = yn[pf->IsStronglyNamed];
				break;
			case iFrozen:
				pszText = yn[pf->IsFrozen];
				break;
			} 

			wcscpy_s(Item.pszText, Item.cchTextMax, pszText);
		}
	}
}

void CDlg::GetTipInfo(NMLVGETINFOTIP* pti)
{
	if (const SYSTEM_PROCESS_INFORMATION* pspi = _pl[pti->iItem])
	{
		HANDLE hProcess;
		CLIENT_ID cid = { pspi->UniqueProcessId };

		NTSTATUS status = NtOpenProcess(&hProcess, PROCESS_QUERY_LIMITED_INFORMATION, const_cast<POBJECT_ATTRIBUTES>(&zoa), &cid);

		if (0 <= status)
		{
			PVOID stack = alloca(guz);

			union {
				PVOID buf;
				PUNICODE_STRING CmdLine;
			};

			ULONG cb = 0, rcb = 0x100;

			do 
			{
				if (cb < rcb) cb = RtlPointerToOffset(buf = alloca(rcb - cb), stack);

				if (0 <= (status = NtQueryInformationProcess(hProcess, ProcessCommandLineInformation, buf, cb, &rcb)))
				{
					swprintf_s(pti->pszText, pti->cchTextMax, L"%wZ", CmdLine);
					break;
				}

			} while (status == STATUS_INFO_LENGTH_MISMATCH);

			NtClose(hProcess);
		}

		if (0 > status)
		{
			if (!FormatMessageW(FORMAT_MESSAGE_IGNORE_INSERTS|FORMAT_MESSAGE_FROM_HMODULE, GetModuleHandle(L"ntdll"), 
				status, 0, pti->pszText, pti->cchTextMax, 0))
			{
				swprintf_s(pti->pszText, pti->cchTextMax, L"error = %x", status);
			}
		}
	}
}

int __cdecl SortByName1(PSYSTEM_PROCESS_INFORMATION& p, PSYSTEM_PROCESS_INFORMATION& q)
{
	return RtlCompareUnicodeString(&p->ImageName, &q->ImageName, TRUE);
}

int __cdecl SortByName2(PSYSTEM_PROCESS_INFORMATION& p, PSYSTEM_PROCESS_INFORMATION& q)
{
	return RtlCompareUnicodeString(&q->ImageName, &p->ImageName, TRUE);
}

int __cdecl SortByOrder1(PSYSTEM_PROCESS_INFORMATION& p, PSYSTEM_PROCESS_INFORMATION& q)
{
	ULONG a = get_Number(p);
	ULONG b = get_Number(q);

	if (a < b) return -1;
	if (a > b) return +1;

	return 0;
}

int __cdecl SortByOrder2(PSYSTEM_PROCESS_INFORMATION& p, PSYSTEM_PROCESS_INFORMATION& q)
{
	ULONG a = get_Number(q);
	ULONG b = get_Number(p);

	if (a < b) return -1;
	if (a > b) return +1;

	return 0;
}

int __cdecl SortByPid1(PSYSTEM_PROCESS_INFORMATION& p, PSYSTEM_PROCESS_INFORMATION& q)
{
	ULONG_PTR a = (ULONG_PTR)p->UniqueProcessId;
	ULONG_PTR b = (ULONG_PTR)q->UniqueProcessId;

	if (a < b) return -1;
	if (a > b) return +1;

	return 0;
}

int __cdecl SortByPid2(PSYSTEM_PROCESS_INFORMATION& p, PSYSTEM_PROCESS_INFORMATION& q)
{
	ULONG_PTR a = (ULONG_PTR)q->UniqueProcessId;
	ULONG_PTR b = (ULONG_PTR)p->UniqueProcessId;

	if (a < b) return -1;
	if (a > b) return +1;

	return 0;
}

int __cdecl SortByFrom1(PSYSTEM_PROCESS_INFORMATION& p, PSYSTEM_PROCESS_INFORMATION& q)
{
	ULONG_PTR a = (ULONG_PTR)p->InheritedFromUniqueProcessId;
	ULONG_PTR b = (ULONG_PTR)q->InheritedFromUniqueProcessId;

	if (a < b) return -1;
	if (a > b) return +1;

	return 0;
}

int __cdecl SortByFrom2(PSYSTEM_PROCESS_INFORMATION& p, PSYSTEM_PROCESS_INFORMATION& q)
{
	ULONG_PTR a = (ULONG_PTR)q->InheritedFromUniqueProcessId;
	ULONG_PTR b = (ULONG_PTR)p->InheritedFromUniqueProcessId;

	if (a < b) return -1;
	if (a > b) return +1;

	return 0;
}

int __cdecl SortByIL1(PSYSTEM_PROCESS_INFORMATION& p, PSYSTEM_PROCESS_INFORMATION& q)
{
	ULONG a = get_IL(p);
	ULONG b = get_IL(q);

	if (a < b) return -1;
	if (a > b) return +1;

	return RtlCompareUnicodeString(&p->ImageName, &q->ImageName, TRUE);
}

int __cdecl SortByIL2(PSYSTEM_PROCESS_INFORMATION& p, PSYSTEM_PROCESS_INFORMATION& q)
{
	ULONG a = get_IL(q);
	ULONG b = get_IL(p);

	if (a < b) return -1;
	if (a > b) return +1;

	return RtlCompareUnicodeString(&q->ImageName, &p->ImageName, TRUE);
}

int __cdecl SortByBreakOn1(PSYSTEM_PROCESS_INFORMATION& p, PSYSTEM_PROCESS_INFORMATION& q)
{
	ULONG a = GetProcessFlags(p)->IsBreakOnTermination;
	ULONG b = GetProcessFlags(q)->IsBreakOnTermination;

	if (a < b) return -1;
	if (a > b) return +1;

	return SortByOrder1(p, q);
}

int __cdecl SortByBreakOn2(PSYSTEM_PROCESS_INFORMATION& p, PSYSTEM_PROCESS_INFORMATION& q)
{
	ULONG a = GetProcessFlags(q)->IsBreakOnTermination;
	ULONG b = GetProcessFlags(p)->IsBreakOnTermination;

	if (a < b) return -1;
	if (a > b) return +1;

	return SortByOrder2(p, q);
}

int __cdecl SortByWow1(PSYSTEM_PROCESS_INFORMATION& p, PSYSTEM_PROCESS_INFORMATION& q)
{
	ULONG a = GetProcessFlags(p)->IsWow64Process;
	ULONG b = GetProcessFlags(q)->IsWow64Process;

	if (a < b) return -1;
	if (a > b) return +1;

	return SortByOrder1(p, q);
}

int __cdecl SortByBreakWow2(PSYSTEM_PROCESS_INFORMATION& p, PSYSTEM_PROCESS_INFORMATION& q)
{
	ULONG a = GetProcessFlags(q)->IsWow64Process;
	ULONG b = GetProcessFlags(p)->IsWow64Process;

	if (a < b) return -1;
	if (a > b) return +1;

	return SortByOrder2(p, q);
}

int __cdecl SortByCross1(PSYSTEM_PROCESS_INFORMATION& p, PSYSTEM_PROCESS_INFORMATION& q)
{
	ULONG a = GetProcessFlags(p)->IsCrossSessionCreate;
	ULONG b = GetProcessFlags(q)->IsCrossSessionCreate;

	if (a < b) return -1;
	if (a > b) return +1;

	return SortByOrder1(p, q);
}

int __cdecl SortByCross2(PSYSTEM_PROCESS_INFORMATION& p, PSYSTEM_PROCESS_INFORMATION& q)
{
	ULONG a = GetProcessFlags(q)->IsCrossSessionCreate;
	ULONG b = GetProcessFlags(p)->IsCrossSessionCreate;

	if (a < b) return -1;
	if (a > b) return +1;

	return SortByOrder2(p, q);
}

int __cdecl SortByProtected1(PSYSTEM_PROCESS_INFORMATION& p, PSYSTEM_PROCESS_INFORMATION& q)
{
	ULONG a = GetProcessFlags(p)->IsProtectedProcess;
	ULONG b = GetProcessFlags(q)->IsProtectedProcess;

	if (a < b) return -1;
	if (a > b) return +1;

	return SortByOrder1(p, q);
}

int __cdecl SortByProtected2(PSYSTEM_PROCESS_INFORMATION& p, PSYSTEM_PROCESS_INFORMATION& q)
{
	ULONG a = GetProcessFlags(q)->IsProtectedProcess;
	ULONG b = GetProcessFlags(p)->IsProtectedProcess;

	if (a < b) return -1;
	if (a > b) return +1;

	return SortByOrder2(p, q);
}

int __cdecl SortByStrong1(PSYSTEM_PROCESS_INFORMATION& p, PSYSTEM_PROCESS_INFORMATION& q)
{
	ULONG a = GetProcessFlags(p)->IsStronglyNamed;
	ULONG b = GetProcessFlags(q)->IsStronglyNamed;

	if (a < b) return -1;
	if (a > b) return +1;

	return SortByOrder1(p, q);
}

int __cdecl SortByStrong2(PSYSTEM_PROCESS_INFORMATION& p, PSYSTEM_PROCESS_INFORMATION& q)
{
	ULONG a = GetProcessFlags(q)->IsStronglyNamed;
	ULONG b = GetProcessFlags(p)->IsStronglyNamed;

	if (a < b) return -1;
	if (a > b) return +1;

	return SortByOrder2(p, q);
}

int __cdecl SortByApp1(PSYSTEM_PROCESS_INFORMATION& p, PSYSTEM_PROCESS_INFORMATION& q)
{
	ULONG a = GetProcessFlags(p)->IsAppContainer;
	ULONG b = GetProcessFlags(q)->IsAppContainer;

	if (a < b) return -1;
	if (a > b) return +1;

	return SortByOrder1(p, q);
}

int __cdecl SortByApp2(PSYSTEM_PROCESS_INFORMATION& p, PSYSTEM_PROCESS_INFORMATION& q)
{
	ULONG a = GetProcessFlags(q)->IsAppContainer;
	ULONG b = GetProcessFlags(p)->IsAppContainer;

	if (a < b) return -1;
	if (a > b) return +1;

	return SortByOrder2(p, q);
}

int __cdecl SortByJob1(PSYSTEM_PROCESS_INFORMATION& p, PSYSTEM_PROCESS_INFORMATION& q)
{
	ULONG a = GetProcessFlags(p)->IsInJob;
	ULONG b = GetProcessFlags(q)->IsInJob;

	if (a < b) return -1;
	if (a > b) return +1;

	return SortByOrder1(p, q);
}

int __cdecl SortByJob2(PSYSTEM_PROCESS_INFORMATION& p, PSYSTEM_PROCESS_INFORMATION& q)
{
	ULONG a = GetProcessFlags(q)->IsInJob;
	ULONG b = GetProcessFlags(p)->IsInJob;

	if (a < b) return -1;
	if (a > b) return +1;

	return SortByOrder2(p, q);
}

int __cdecl SortByFrozen1(PSYSTEM_PROCESS_INFORMATION& p, PSYSTEM_PROCESS_INFORMATION& q)
{
	ULONG a = GetProcessFlags(p)->IsFrozen;
	ULONG b = GetProcessFlags(q)->IsFrozen;

	if (a < b) return -1;
	if (a > b) return +1;

	return SortByOrder1(p, q);
}

int __cdecl SortByFrozen2(PSYSTEM_PROCESS_INFORMATION& p, PSYSTEM_PROCESS_INFORMATION& q)
{
	ULONG a = GetProcessFlags(q)->IsFrozen;
	ULONG b = GetProcessFlags(p)->IsFrozen;

	if (a < b) return -1;
	if (a > b) return +1;

	return SortByOrder2(p, q);
}

int __cdecl SortBySession1(PSYSTEM_PROCESS_INFORMATION& p, PSYSTEM_PROCESS_INFORMATION& q)
{
	ULONG a = p->SessionId;
	ULONG b = q->SessionId;

	if (a < b) return -1;
	if (a > b) return +1;

	return SortByOrder2(p, q);
}

int __cdecl SortBySession2(PSYSTEM_PROCESS_INFORMATION& p, PSYSTEM_PROCESS_INFORMATION& q)
{
	ULONG a = q->SessionId;
	ULONG b = p->SessionId;

	if (a < b) return -1;
	if (a > b) return +1;

	return SortByOrder2(p, q);
}

void CDlg::OnColumClick(ULONG iSubItem, HWND hwndLV)
{
	if (OnColumClick(iSubItem))
	{
		LVCOLUMN lc = { LVCF_FMT, LVCFMT_LEFT };

		if (_iSubItem != iSubItem)
		{
			ListView_SetColumn(hwndLV, _iSubItem, &lc);
			_iSubItem = iSubItem;
		}

		lc.fmt = 0 < _s[iSubItem] ? LVCFMT_LEFT|HDF_SORTDOWN : LVCFMT_LEFT|HDF_SORTUP;

		ListView_SetColumn(hwndLV, iSubItem, &lc);

		InvalidateRect(hwndLV, 0, 0);
	}
}

bool CDlg::OnColumClick(ULONG iSubItem)
{
	if (iSubItem < iMax)
	{
		int s = -_s[iSubItem];

		_s[iSubItem] = s;

		switch (iSubItem)
		{
		case iNumber:
			_pl(s < 0 ? SortByOrder1 : SortByOrder2);
			return true;
		case iFrom:
			_pl(s < 0 ? SortByFrom1 : SortByFrom2);
			return true;
		case iPID:
			_pl(s < 0 ? SortByPid1 : SortByPid2);
			return true;
		case iName:
			_pl(s < 0 ? SortByName1 : SortByName2);
			return true;
		case iSession:
			_pl(s < 0 ? SortBySession1 : SortBySession2);
			return true;
		case iLevel:
			_pl(s < 0 ? SortByIL1 : SortByIL2);
			return true;
		case iBreakOnTermination:
			_pl(s < 0 ? SortByBreakOn1 : SortByBreakOn2);
			return true;
		case iCrossSessionCreate:
			_pl(s < 0 ? SortByCross1 : SortByCross2);
			return true;
		case iProtectedProcess:
			_pl(s < 0 ? SortByProtected1 : SortByProtected2);
			return true;
		case iWow64Process:
			_pl(s < 0 ? SortByWow1 : SortByBreakWow2);
			return true;
		case iStronglyNamed:
			_pl(s < 0 ? SortByStrong1 : SortByStrong2);
			return true;
		case iAppContainer:
			_pl(s < 0 ? SortByApp1 : SortByApp2);
			return true;
		case iInJob:
			_pl(s < 0 ? SortByJob1 : SortByJob2);
			return true;
		case iFrozen:
			_pl(s < 0 ? SortByFrozen1 : SortByFrozen2);
			return true;
		}
	}

	return false;
}

void ep()
{
	initterm();
	BOOLEAN b;
	RtlAdjustPrivilege(SE_DEBUG_PRIVILEGE, TRUE, FALSE, &b);
	{
		CDlg dlg;
		dlg.DoModal((HINSTANCE)&__ImageBase, MAKEINTRESOURCEW(IDD_DIALOG1), 0, 0);
	}
	destroyterm();
	ExitProcess(0);
}

_NT_END