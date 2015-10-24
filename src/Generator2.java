

import uniandes.gload.core.LoadGenerator;
import uniandes.gload.core.Task;

public class Generator2 {
	public ClientTaskServer2 work;
	public int numberOfTasks=0;
	private LoadGenerator generator;
	public Generator2(){
		 
		numberOfTasks=900;
		work =createTask(numberOfTasks);
		int gapBeetwenTasks=80;
		generator=new LoadGenerator("Client Server load test", numberOfTasks, work, gapBeetwenTasks);
		generator.generate();
		
		
	}
	
	private ClientTaskServer2 createTask(int n){
		return new ClientTaskServer2( n);
	}
	
	public static void main(String[] args) {
		Generator2 gen=new Generator2();
		
	}

}
