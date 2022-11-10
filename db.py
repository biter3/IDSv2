import sqlite3

#create database
conn = sqlite3.connect('ids.db')

c = conn.cursor()

#create a table to store malicious packets
c.execute("""CREATE TABLE IF NOT EXISTS malicious_packets (
	date_time text,
	source_ip text,
	source_port text,
	destination_ip text,
	destination_port text,
	protocol text,
	severity text,
	message text
	)""")

conn.commit()

conn.close()


class myDB:

		
	
	def updateDB(date_time, protocol, source, src_port, destination, dest_port , severity, check_ddos):
	
		print("================+HEEREE======================")
		#error/success message
		message = ""
		
		print(source)
		print(src_port)
		print(destination)
		print(dest_port)
		print(protocol)
		print(severity)
		
		#query
		#sql = "INSERT INTO malicious_packets VALUES (?,?,?,?,?,?)"
	
		
		#connect
		conn = sqlite3.connect('ids.db')
		
		#create cursor
		c = conn.cursor()
		
		c.execute("INSERT INTO malicious_packets VALUES (?,?,?,?,?,?,?,?)", (str(date_time), source, str(src_port), destination, str(dest_port), protocol, severity, check_ddos))
		
		conn.commit()
		
		conn.close()
		
		message = "Record added"
		
		print("************** DATA ADDED **********************")
			

		
		return message

