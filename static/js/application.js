$(document).ready(function(){

var data_received = [];
var id = 0;

	$("#start").click(function(){
		var buttonId = this.id;
		document.getElementById("start").disabled = true;

		//connect to the socket server.
		var socket = io.connect('http://' + document.domain + ':' + location.port + '/test');

		//receive details from server
		socket.on('newnumber', function(msg) {
			
			var table = document.getElementById("dataTable");
			var row = '';
			
			console.log("Received Data" + msg.data);
		
			console.log(msg.data)
			data_received.push(msg.data);
			var data_string = '';

			for (var i = 0; i < data_received.length; i++)
			{
				//insert table with 6 cells
				row = table.insertRow(1);
				
				
				for(var j = 0; j < data_received[i].length-1; j++) //changed this, no more -1 at the end
				{
					if(String(data_received[i][6]) == "low")
					{
						cell = row.insertCell(j);
						cell.innerHTML = String(data_received[i][j]).fontcolor("blue");
					}
					else if(String(data_received[i][6]) == "medium")
					{
						cell = row.insertCell(j);
						cell.innerHTML = String(data_received[i][j]).fontcolor("orange");
					}
					else if(String(data_received[i][6]) == "high")
					{
						cell = row.insertCell(j);
						cell.innerHTML = String(data_received[i][j]).fontcolor("red");
					}
					else
					{
						cell = row.insertCell(j);
						cell.innerHTML = String(data_received[i][j]);
						
						var Packet = {
							date_time : String(data_received[i][0]),
							source_ip : String(data_received[i][1]),
							source_port : String(data_received[i][2]),
							dest_ip : String(data_received[i][3]),
							dest_port : String(data_received[i][4]),
							proto : String(data_received[i][5]),
							severity : String(data_received[i][6]),
							msg : String(data_received[i][7]),
							data : String(data_received[i][8])
						};
						
						localStorage.setItem(`packet${id}`, JSON.stringify(Packet)); //storing the variables in localstorage
					}
							
				}
				
				//new code for button
				button = row.insertCell(8); //Last row after message

				button.innerHTML = `<button onclick="myFunction(${id})" class="btn btn-info btn-lg" id="${id}">View</button>`;
				
				//id increment for unique button id
				id++;
			}
			
			//total number of packets
			localStorage.setItem("id", id);

		    });
	}); 
	
	//export button clicked
	$("#export").click(function(){
		console.log("Export button pressed");
		
		var socket = io.connect('http://' + document.domain + ':' + location.port + '/test');
		
		socket.send("export");
		
	});
	
});
