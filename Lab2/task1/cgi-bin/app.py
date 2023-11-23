import cgi

form = cgi.FieldStorage()

pizza_type = form.getvalue("pizza_type")
toppings = form.getlist("topping")
pizza_size = form.getvalue("pizza_size")

print("Content-type: text/html\n")
print("<html>")
print("<head><title>Pizza order result</title></head>")
print("<link rel='stylesheet' href='../stylesheet/style.css'>")
print("<body>")
print("<center>")
print("<br>")
print("<h1>Your order:</h1>")
print("<form>")
print("<p>Type of pizza:{}</p>".format(pizza_type))
print("<p>Additional ingredients:")
for topping in toppings:
    print("<br>{}".format(topping))
print("</p>")
print("<p>Pizza size:{}</p>".format(pizza_size))
print("</form>")
print("</center>")
print("</body>")
print("</html>")