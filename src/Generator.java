

import uniandes.gload.core.LoadGenerator;
import uniandes.gload.core.Task;

public class Generator {
	public ClientServerTask work;
	public int numberOfTasks=0;
	private LoadGenerator generator;
	public Generator(){
		 
		numberOfTasks=900;
		work =createTask(numberOfTasks);
		int gapBeetwenTasks=80;
		generator=new LoadGenerator("Client Server load test", numberOfTasks, work, gapBeetwenTasks);
		generator.generate();
		
		
	}
	
	private ClientServerTask createTask(int n){
		return new ClientServerTask( n);
	}
	
	public static void main(String[] args) {
		Generator gen=new Generator();
		
	}

}
