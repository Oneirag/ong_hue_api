import pandas as pd

from ong_utils import is_windows

if is_windows:
    from ong_utils.office.office_base import ExcelBase
from ong_hue_api.logs import create_logger
from ong_utils import is_windows

if is_windows:
    class Excel(ExcelBase):

        def __init__(self):
            super().__init__(create_logger())

        def workbook(self, workbook_name: str):
            """Returns the first workbook which name matches given one"""
            # Firstly, check if there is any opened workbook with this name. If so, use it
            for wb in self.client.Workbooks:
                if wb.Name == workbook_name:
                    return wb
            wb = self.client.Workbooks.Add()
            wb.Name = workbook_name
            return wb

        def set_df(self, df: pd.DataFrame, wb_name: str, sheet_name: str, start_cell_row: int = 1,
                   start_cell_col: int = 1):
            """
            Writes the given DataFrame in the given workbook and sheet. Deletes all previous data!
            :param df: DataFrame to write in Excel. Dates cannot be naive, they must have a timezone
            :param wb_name: name of the workbook. Iif it is not already opened, then a new one will be created
            :param sheet_name: name of the sheet. Creates a new sheet if it does not exist
            :param start_cell_row: starting row for inserting data. Defaults to 1 (first row, it is 1-based not 0-based)
            :param start_cell_col: starting column for inserting data. Defaults to 1 (first row, it is 1-based not 0-based)
            :return: None
            """
            wb = self.workbook(wb_name)
            if wb:
                try:
                    sheet = wb.Worksheets[sheet_name]
                except:
                    # Probably sheet does not exit: create it
                    sheet = wb.Worksheets.Add()
                    sheet.Name = sheet_name
                rows, cols = df.shape
                sheet.UsedRange.Clear()
                sheet.Range(sheet.Cells(1, 1), sheet.Cells(1, cols)).Value = df.columns
                sheet.Range(sheet.Cells(2, 1), sheet.Cells(rows + 1, cols)).Value = df.values


def csv2df(file: str, convert_dates: bool = True) -> pd.DataFrame:
    df = pd.read_csv(file)
    if convert_dates:
        for col in df.columns:
            if col.startswith("dat_") or col.startswith("dat_"):
                df[col] = pd.to_datetime(df[col])
                df[col].dt.tz_localize(None)
    return df


def df2openxls(df: pd.DataFrame, workbook: str, sheet: str):
    """Writes given df into given already opened excel workbook in given sheet"""
    if not is_windows:
        return  # windows only!
    xls = Excel()
    xls.set_df(df, workbook, sheet)
