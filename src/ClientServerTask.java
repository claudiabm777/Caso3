import java.io.File;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

import jxl.CellView;
import jxl.Workbook;
import jxl.WorkbookSettings;
import jxl.format.UnderlineStyle;
import jxl.write.Label;
import jxl.write.Number;
import jxl.write.WritableCellFormat;
import jxl.write.WritableFont;
import jxl.write.WritableSheet;
import jxl.write.WritableWorkbook;
import jxl.write.WriteException;
import jxl.write.biff.RowsExceededException;
import uniandes.gload.core.Task;


public class ClientServerTask extends Task {
	private WritableCellFormat timesBoldUnderline; //ATRIBUTO PARA IMPRIMIR EN ARCHIVO EXCEL
	private WritableCellFormat times; //ATRIBUTO PARA IMPRIMIR EN ARCHIVO EXCEL
	public double numeroExitosos=0;
	public int n;
	public double noExitosos=0;
	public List<Double>tiempoRespuestas=new ArrayList<Double>();
	public List<Double>tiempoAtus=new ArrayList<Double>();
	public List<Double>CPU=new ArrayList<Double>();
	public ClientServerTask(int n){
		this.n=n;
	}
	public void execute(){
		try {
			Cliente cliente=new Cliente();
			success();
			tiempoRespuestas.add(cliente.tRespuesta);
			tiempoAtus.add(cliente.tAutenticacion);
			CPU.add(cliente.cpuUsage);
			numeroExitosos++;
			
			n--;
			imprimir();
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			fail();
			noExitosos++;
			
			n--;
			imprimir();
		}
	}
	public void imprimir(){
		try{
		if(n==0){
			System.out.println("Num exitosos: "+numeroExitosos);
			System.out.println("Num fallidos: "+noExitosos);
			System.out.println("Lista num: "+tiempoRespuestas.toString());
			WorkbookSettings wbSettings = new WorkbookSettings();
			 File f = new File("ConSeguridad.xls");
		    wbSettings.setLocale(new Locale("en", "EN"));
			WritableWorkbook workbook = Workbook.createWorkbook(f, wbSettings);
		    workbook.createSheet("Resultados",0);
		    createLabel();
		    WritableSheet excelSheet = workbook.getSheet(0);
		    addLabel(excelSheet, 1, 1, "Tiempo Autenticacion");
		    addLabel(excelSheet, 2, 1, "Tiempo Respuesta");
		    addLabel(excelSheet, 3, 1, "Porcentaje CPU");
		    addLabel(excelSheet, 4, 1, "Numero solicitudes exitosas");
		    addLabel(excelSheet, 5, 1, "Numero solicitudes no exitosas");
		    addNumber(excelSheet, 4, 2, numeroExitosos);
		    addNumber(excelSheet, 5, 2, noExitosos);
		    for (int i = 0; i < tiempoRespuestas.size(); i++) {
		    	 addNumber(excelSheet, 2, i+2, tiempoRespuestas.get(i));
			}
		    for (int i = 0; i < tiempoAtus.size(); i++) {
		    	addNumber(excelSheet, 1, i+2, tiempoAtus.get(i));
			}
		    for (int i = 0; i < CPU.size(); i++) {
		    	addNumber(excelSheet, 3, i+2, CPU.get(i));
			}
    workbook.write();
    workbook.close();
    System.out.println("Num exitosos: "+numeroExitosos);
	System.out.println("Num fallidos: "+noExitosos);
	System.out.println("Lista num: "+tiempoRespuestas.toString());
		}
		}catch(Exception e){
			e.printStackTrace();
		}
	}
	 public void createLabel() throws WriteException {
		    // Lets create a times font
		    WritableFont times10pt = new WritableFont(WritableFont.TIMES, 10);
		    // Define the cell format
		    times = new WritableCellFormat(times10pt);
		    // Lets automatically wrap the cells
		    times.setWrap(true);

		    // create create a bold font with unterlines
		    WritableFont times10ptBoldUnderline = new WritableFont(WritableFont.TIMES, 10, WritableFont.BOLD, false,UnderlineStyle.SINGLE);
		    timesBoldUnderline = new WritableCellFormat(times10ptBoldUnderline);
		    // Lets automatically wrap the cells
		    timesBoldUnderline.setWrap(true);

		    CellView cv = new CellView();
		    cv.setFormat(times);
		    cv.setFormat(timesBoldUnderline);
		    cv.setAutosize(true);

		    

		  }
	  
	 public void addLabel(WritableSheet sheet, int column, int row, String s) throws WriteException, RowsExceededException {
		    Label label;
		    label = new Label(column, row, s, times);
		    sheet.addCell(label);
		  }
	 public void addNumber(WritableSheet sheet, int column, int row,Double num) throws WriteException, RowsExceededException {
		  Number number;
		    number = new Number(column, row, num, times);
		    sheet.addCell(number);
		  }
	@Override
	public void fail() {
		// TODO Auto-generated method stub
		System.out.println("FAIL!!!!!!!!!!!!!!!!!!");
		
	}
	
	
	@Override
	public void success() {
		// TODO Auto-generated method stub
		System.out.println("SUCCES!!!!!!!!!!!!!!!");
	}

}
