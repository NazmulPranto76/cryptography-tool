def parse_key(key_str):
    # Input:  "3 1 2"
    # Output: [3, 1, 2]
    try:
        return list(map(int, key_str.strip().split()))
    except ValueError:
        return None

def _row_transpose_encrypt(text, key):
    # Input:  "ABCDEF", [2, 1]
    # Output: "DEFABC"  (2 rows: ABC / DEF → read row 2 first, then row 1)
    num_rows = len(key)
    cols = (len(text) + num_rows - 1) // num_rows

    while len(text) < num_rows * cols:
        text += 'X'

    grid = []
    for i in range(num_rows):
        grid.append(text[i * cols:(i + 1) * cols])

    result = ""
    for row_num in key:
        result += grid[row_num - 1]
    return result

def _row_transpose_decrypt(text, key):
    # Input:  "DEFABC", [2, 1]
    # Output: "ABCDEF"
    num_rows = len(key)
    cols = len(text) // num_rows

    encrypted_rows = []
    for i in range(num_rows):
        encrypted_rows.append(text[i * cols:(i + 1) * cols])

    original_rows = [''] * num_rows
    for i, row_num in enumerate(key):
        original_rows[row_num - 1] = encrypted_rows[i]
    return "".join(original_rows)

def _col_transpose_encrypt(text, key):
    # Input:  "OXHELL", [2, 1, 3]
    # Grid:
    # O X H
    # E L L
    # XL + OE + HL = XLOEHL

    num_cols = len(key)

    while len(text) % num_cols != 0:
        text += 'X'

    num_rows = len(text) // num_cols

    grid = []
    for i in range(num_rows):
        row = list(text[i * num_cols:(i + 1) * num_cols])
        grid.append(row)

    result = ""
    for col_num in key:
        for row in grid:
            result += row[col_num - 1]

    return result

def _col_transpose_decrypt(text, key):
    # Input:  "XLOEHL", [2, 1, 3]
    # Encrypted columns:
    # Column 2 got XL
    # Column 1 got OE
    # Column 3 got HL
    # Rebuild original grid:
    # O X H
    # E L L
    # Output: "OXHELL"

    num_cols = len(key)
    num_rows = len(text) // num_cols

    grid = []
    for _ in range(num_rows):
        grid.append([''] * num_cols)

    index = 0

    for col_num in key:
        for row_index in range(num_rows):
            grid[row_index][col_num - 1] = text[index]
            index += 1

    result = ""
    for row in grid:
        result += "".join(row)

    return result

def encrypt(plaintext, key1, key2):
    # Input:  "HELLO", [3, 1, 2], [2, 1, 3]
    # Output: ("OXHELL", "XOHLEL")
    text = plaintext.upper().replace(' ', '')
    after_rows = _row_transpose_encrypt(text, key1)
    final = _col_transpose_encrypt(after_rows, key2)
    return after_rows, final

def encrypt_trace(plaintext, key1, key2):
    # Input:  "HELLO WORLD", [3,1,4,2], [2,4,1,3]
    # Output: dict with 'steps' list showing the grid at each stage
    text = plaintext.upper().replace(' ', '')
    nr1  = len(key1)
    cols1 = (len(text) + nr1 - 1) // nr1
    while len(text) < nr1 * cols1:
        text += 'X'
    grid1 = [list(text[i * cols1:(i + 1) * cols1]) for i in range(nr1)]

    steps = []
    steps.append({
        "name":  "Fill Grid (Row Transposition)",
        "desc":  f"Text written left-to-right into a {nr1}×{cols1} grid. 'X' pads to fill.",
        "phase": "fill1",
        "grid":  [list(r) for r in grid1],
        "key":   list(key1),
        "rows":  nr1, "cols": cols1,
        "text":  None,
    })
    after_rows = ''
    reordered_grid1 = []
    for row_num in key1:
        reordered_grid1.append(grid1[row_num - 1])
        after_rows += ''.join(grid1[row_num - 1])

    steps.append({
        "name":  "Row Transposition — Key 1",
        "desc":  f"Rows read in the order given by key1 = {list(key1)}.",
        "phase": "row_transpose",
        "grid":  [list(r) for r in reordered_grid1],
        "key":   list(key1),
        "rows":  nr1, "cols": cols1,
        "text":  after_rows,
    })
    nc2  = len(key2)
    while len(after_rows) % nc2 != 0:
        after_rows += 'X'
    nr2   = len(after_rows) // nc2
    grid2 = [list(after_rows[i * nc2:(i + 1) * nc2]) for i in range(nr2)]

    steps.append({
        "name":  "Fill Grid (Column Transposition)",
        "desc":  f"Row-transposition result fills a {nr2}×{nc2} grid.",
        "phase": "fill2",
        "grid":  [list(r) for r in grid2],
        "key":   list(key2),
        "rows":  nr2, "cols": nc2,
        "text":  None,
    })
    result = ''
    for col_num in key2:
        for row in grid2:
            result += row[col_num - 1]

    steps.append({
        "name":  "Column Transposition — Key 2",
        "desc":  f"Columns read in the order given by key2 = {list(key2)}.",
        "phase": "col_transpose",
        "grid":  [list(r) for r in grid2],
        "key":   list(key2),
        "rows":  nr2, "cols": nc2,
        "text":  result,
    })

    steps.append({
        "name":  "Ciphertext",
        "desc":  "Final encrypted output after both transpositions.",
        "phase": "output",
        "grid":  None,
        "key":   None,
        "rows":  None, "cols": None,
        "text":  result,
    })

    return {
        "steps":      steps,
        "key1":       list(key1),
        "key2":       list(key2),
        "plaintext":  plaintext.upper().replace(' ', ''),
        "ciphertext": result,
        "num_steps":  len(steps),
    }

def decrypt(ciphertext, key1, key2):
    # Input:  "XOHLEL", [3, 1, 2], [2, 1, 3]
    # Output: "HELLOX"  (trailing X is padding)
    after_col = _col_transpose_decrypt(ciphertext, key2)
    plaintext = _row_transpose_decrypt(after_col, key1)
    return plaintext
