<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Animal Photo Repository</title>
    <style>
        body {
            font-family: 'Comic Sans MS', 'Helvetica Neue', Arial, sans-serif;
            background: #f0f0f0;
            display: flex;
            flex-direction: column;
            align-items: center;
            margin: 0;
            padding: 20px;
            color: #333333;
            position: relative;
            min-height: 100vh;
        }
        table {
            width: 90%;
            max-width: 1200px;
            margin-top: 20px;
            border-collapse: collapse;
            box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
        }
        th, td {
            padding: 15px 20px;
            text-align: left;
            vertical-align: top;
            border: 1px solid #dddddd;
        }
        th {
            background-color: #333333;
            color: white;
            font-size: 1.2em;
        }
        td {
            background-color: #ffffff;
            color: #333333;
            font-size: 1em;
        }
        td a {
            text-decoration: none;
            color: #333333;
            transition: color 0.3s ease, transform 0.3s ease;
            display: block;
            margin-bottom: 5px;
        }
        td a:hover {
            color: #000000;
            transform: scale(1.05);
        }
        h1 {
            font-size: 2.5em;
            color: #333333;
            margin-bottom: 20px;
            border-bottom: 2px solid #333333;
            padding-bottom: 10px;
            display: flex;
            align-items: center;
        }
        .note {
            font-size: 0.8em;
            color: #666666;
            position: absolute;
            bottom: 10px;
            right: 10px;
        }
        @keyframes fadeIn {
            0% { opacity: 0; }
            100% { opacity: 1; }
        }
        @media (max-width: 768px) {
            body {
                padding: 10px;
            }
            table {
                width: 100%;
            }
            th, td {
                padding: 10px;
            }
            h1 {
                font-size: 2em;
            }
        }
    </style>
</head>
<body>
    <h1>Animal Photo Repository</h1>
    <table>
        <thead>
            <tr>
                <th>Animal Type</th>
                <th>Profile Pictures</th>
            </tr>
        </thead>
        <tbody>
            <tr>
                <td><a href="https://en.wikipedia.org/wiki/Panda">Pandas</a></td>
                <td>
                    <a href="view.php?animal=PANDA1.jpg">Panda 1</a>
                    <a href="view.php?animal=PANDA2.jpg">Panda 2</a>
                    <a href="view.php?animal=PANDA3.jpg">Panda 3</a>
                </td>
            </tr>
            <tr>
                <td><a href="https://en.wikipedia.org/wiki/Platypus">Platypus</a></td>
                <td>
                    <a href="view.php?animal=PLATYPUS1.jpg">Platypus 1</a>
                    <a href="view.php?animal=PLATYPUS2.jpg">Platypus 2</a>
                    <a href="view.php?animal=PLATYPUS3.jpg">Platypus 3</a>
                </td>
            </tr>
            <tr>
                <td><a href="https://en.wikipedia.org/wiki/Rabbit">Rabbits</a></td>
                <td>
                    <a href="view.php?animal=RABBIT1.jpg">Rabbit 1</a>
                    <a href="view.php?animal=RABBIT2.jpg">Rabbit 2</a>
                    <a href="view.php?animal=RABBIT3.jpg">Rabbit 3</a>
                </td>
            </tr>
            <tr>
                <td><a href="https://en.wikipedia.org/wiki/Cat">Cats</a></td>
                <td>
                    <a href="view.php?animal=CAT1.jpg">Cat 1</a>
                    <a href="view.php?animal=CAT2.jpg">Cat 2</a>
                    <a href="view.php?animal=CAT3.jpg">Cat 3</a>
                </td>
            </tr>
            <tr>
                <td><a href="https://en.wikipedia.org/wiki/Lion">Lions</a></td>
                <td>
                    <a href="view.php?animal=LION1.jpg">Lion 1</a>
                    <a href="view.php?animal=LION2.jpg">Lion 2</a>
                    <a href="view.php?animal=LION3.jpg">Lion 3</a>
                </td>
            </tr>
            <!-- Add more animals and profile pictures as needed -->
        </tbody>
    </table>
    <div class="note">Images created by ChatGPT</div>
</body>
</html>
