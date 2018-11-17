public class MainProgramm {
    public static void main (String[] arguments){
        try {
            Abonent abonent1 = new Abonent();
            Abonent abonent2 = new Abonent();
        
            for(int i = 0; i < 2; i++) {
                String x = abonent1.encrypt("Hello abonent2!" + i);
                System.out.print(x + "\n");
        
                String y = abonent2.decrypt(x);
                System.out.print(y + "\n");        
            }
        }
        catch(Exception ex) {
            ex.printStackTrace();
        }
    }
}
