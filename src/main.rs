use sha256::hash;

// ################ some shit to print things ################

trait Printable {
    fn print(&self);
}

impl<const N: usize> Printable for [u8; N] {
    fn print(&self) {
        let hex_groups = self
            .chunks(2)
            .map(|pair| match pair.len() {
                1 => format!("{:02X}", pair[0]),
                _ => format!("{:02X} {:02X}", pair[0], pair[1]),
            })
            .collect::<Vec<String>>();

        for group in hex_groups.chunks(8) {
            println!("{}", group.join(" ").trim_end());
        }
    }
}

fn print_data<T: Printable>(data: &T) {
    data.print();
}

// ###########################################################

fn main() {
    let input = "Hello";

    let hash_result = hash(input);

    println!("Result:");
    print_data(&hash_result);
}
